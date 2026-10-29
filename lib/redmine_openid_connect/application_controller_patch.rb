module RedmineOpenidConnect
  module ApplicationControllerPatch
    # SPR-546: the product signs in through Keycloak only. Redmine's own credentials are never
    # looked at: the per-user API key (`?key=`, `X-Redmine-API-Key`, also as the Basic user
    # name), Basic with a login and password, Redmine 7's own OAuth tokens (Doorkeeper) and
    # an admin's `X-Redmine-Switch-User`. Each of them outlived the Keycloak account — an
    # offboarded user kept the API key, and neither logout nor the token TTL touched it.
    #
    # Core reads all of them in one branch of `find_current_user`, guarded by
    # `Setting.rest_api_enabled? && accept_api_auth?`. The setting cannot simply be switched
    # off: `require_login` checks it as well and then answers an API request without a user
    # with 403 instead of 401, and the SPA re-authenticates only on 401. So `accept_api_auth?`
    # says no while the user is being found, and only then. The session cookie of the raw
    # web UI is read before that branch and is not affected.
    def find_current_user(*args, &block)
      user = begin
        @ignore_redmine_credentials = true
        super(*args, &block)
      ensure
        @ignore_redmine_credentials = false
      end
      return user if user

      auth_header = request.headers['Authorization'].to_s
      if auth_header.start_with?('Bearer ')
        token = auth_header.split(' ').last
        user = find_user_by_oidc_token(token)

        if user
          User.current = user
          return user
        end
      end
      user
    end

    def accept_api_auth?(*args)
      return false if @ignore_redmine_credentials

      super
    end

    # SPR-546: the Atom feeds' own `?key=` (a second static per-user key) is refused too. The
    # SPA reads `/activity.atom` with its Bearer token, which does not depend on this.
    def accept_atom_auth?(*)
      false
    end

    private

    def find_user_by_oidc_token(token)
      settings = Setting.plugin_redmine_openid_connect
      base_url = settings['openid_connect_server_url'].to_s.chomp('/')
      return nil if base_url.blank?

      userinfo_url = "#{base_url}/protocol/openid-connect/userinfo"

      begin
        user_data = cached_userinfo(token, userinfo_url)
        return nil unless user_data

        # Reject tokens issued for a user outside this tenant's Identity
        # organization, even when the token itself is valid. The organization
        # claim may live in the access token or in the userinfo response,
        # depending on how the membership mapper is configured.
        unless OicSession.organization_member?(user_data, decode_token_payload(token))
          Rails.logger.warn "OIDC Bearer: user #{user_data['email']} is not a member of " \
                            "organization '#{OicSession.organization_alias}', access refused"
          return nil
        end

        email = user_data['email']
        return nil if email.blank?

        user = User.find_by_mail(email)

        if user.nil? && settings['create_user_if_not_exists']
          user = create_user_from_oidc(user_data)
        end

        # The admin flag is not synced from the token (SPR-383): it belongs to the tracker's
        # role model, and the `groups` claim differed between clients, so every request from a
        # client without it took the flag away again.
        sync_user_names(user, user_data) if user

        user
      rescue OpenSSL::SSL::SSLError => e
        Rails.logger.error "OIDC Bearer: TLS verification of #{userinfo_url} failed (#{e.message}). " \
                           "Certificate checks can no longer be switched off (the disable_ssl_validation " \
                           "setting was removed in SPR-554); give the Identity provider a valid certificate."
        nil
      rescue => e
        Rails.logger.error "OIDC Bearer Exception: #{e.message}"
        nil
      end
    end

    # SPR-561: the longest a userinfo answer is reused. Keycloak access tokens live 5 minutes,
    # so this is also the longest a token revoked in Keycloak (logout, disabled user) keeps
    # working here.
    USERINFO_CACHE_MAX_TTL = 300

    # SPR-561: Keycloak is asked about a token once, not on every request it comes with. The
    # SPA sends the same token with every call for its whole lifetime, and each call used to
    # wait for a synchronous userinfo round trip. Only an answer Keycloak gave with 200 is kept,
    # under a digest of the whole token and no longer than the token's own `exp`, so a forged
    # or altered token never reaches another token's entry and an expired one is asked again.
    def cached_userinfo(token, userinfo_url)
      ttl = userinfo_cache_ttl(token)
      return request_userinfo(token, userinfo_url) unless ttl

      key = "oidc_userinfo/#{Digest::SHA256.hexdigest(token)}"
      cached = Rails.cache.read(key)
      return cached if cached.is_a?(Hash)

      user_data = request_userinfo(token, userinfo_url)
      Rails.cache.write(key, user_data, expires_in: ttl) if user_data
      user_data
    end

    def userinfo_cache_ttl(token)
      exp = decode_token_payload(token)&.dig('exp')
      return nil unless exp.is_a?(Integer)

      ttl = [exp - Time.now.to_i, USERINFO_CACHE_MAX_TTL].min
      ttl.positive? ? ttl : nil
    end

    def request_userinfo(token, userinfo_url)
      uri = URI.parse(userinfo_url)
      http = Net::HTTP.new(uri.host, uri.port)

      if uri.scheme == 'https'
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      end

      request = Net::HTTP::Get.new(uri.request_uri)
      request['Authorization'] = "Bearer #{token}"
      request['Accept'] = 'application/json'

      response = http.request(request)

      unless response.code == '200'
        Rails.logger.error "OIDC Bearer Error: Provider returned #{response.code} - #{response.body}"
        return nil
      end

      user_data = JSON.parse(response.body)
      user_data.is_a?(Hash) ? user_data : nil
    end

    # Decodes the JWT payload of a bearer token without verifying its signature.
    # Safe only because it runs after the userinfo endpoint accepted this very token
    # over a certificate-verified connection: Keycloak checked the signature, so the
    # payload cannot have been altered. It only adds the claims Keycloak put into the
    # access token (e.g. `organization`) to what userinfo returned. `cached_userinfo` reads
    # `exp` before that, but keeps nothing unless userinfo accepts the token, signature and all.
    def decode_token_payload(token)
      payload = token.to_s.split('.')[1]
      return nil if payload.blank?

      payload += '=' * ((4 - payload.length % 4) % 4)
      JSON.parse(Base64.urlsafe_decode64(payload))
    rescue StandardError => e
      Rails.logger.warn "OIDC Bearer: could not decode token payload: #{e.message}"
      nil
    end

    def create_user_from_oidc(user_data)
      user = User.new
      user.login = build_valid_login(user_data)
      return nil if user.login.blank?

      user.mail = user_data['email']
      user.firstname = user_data['given_name'] || 'OIDC'
      user.lastname = user_data['family_name'] || 'User'
      user.random_password
      user.status = User::STATUS_ACTIVE

      if user.save
        user
      else
        Rails.logger.error "OIDC Bearer: Failed to create user: #{user.errors.full_messages}"
        nil
      end
    end

    def build_valid_login(user_data)
      base = user_data['preferred_username'].presence || user_data['email'].to_s
      return nil if base.blank?

      # If it's an email, use part before '@'
      base = base.split('@').first if base.include?('@')

      # Allow only a-z, 0-9, dot, underscore, dash
      login = base.downcase.gsub(/[^a-z0-9._-]/, '_')
      login = login.gsub(/^_+|_+$/, '')
      login = login[0, 50]
      return nil if login.blank?

      unique_login = login
      suffix = 1
      while User.exists?(login: unique_login)
        cut_base = login[0, 50 - (suffix.to_s.length + 1)]
        unique_login = "#{cut_base}-#{suffix}"
        suffix += 1
        break if suffix > 1000
      end

      unique_login
    end

    def sync_user_names(user, user_data)
      firstname = user_data['given_name']
      lastname  = user_data['family_name']

      # Fall back to the "name" claim when given_name/family_name are missing
      if (firstname.blank? || lastname.blank?) && user_data['name'].present?
        parts = user_data['name'].split
        if parts.length >= 2
          firstname = parts.first if firstname.blank?
          lastname  = parts.last  if lastname.blank?
        end
      end

      changed = false
      if firstname.present? && firstname != user.firstname
        user.firstname = firstname
        changed = true
      end
      if lastname.present? && lastname != user.lastname
        user.lastname = lastname
        changed = true
      end

      return unless changed

      if user.save
        Rails.logger.info "OIDC Bearer: Updated names for #{user.login} -> #{user.firstname} #{user.lastname}"
      else
        Rails.logger.error "OIDC Bearer: Failed to update names for #{user.login}: #{user.errors.full_messages}"
      end
    end
  end
end