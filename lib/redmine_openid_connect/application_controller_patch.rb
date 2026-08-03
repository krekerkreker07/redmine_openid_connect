module RedmineOpenidConnect
  module ApplicationControllerPatch
    def find_current_user(*args, &block)
      user = super(*args, &block)
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

    private

    def find_user_by_oidc_token(token)
      settings = Setting.plugin_redmine_openid_connect
      base_url = settings['openid_connect_server_url'].to_s.chomp('/')
      return nil if base_url.blank?

      userinfo_url = "#{base_url}/protocol/openid-connect/userinfo"

      begin
        uri = URI.parse(userinfo_url)
        http = Net::HTTP.new(uri.host, uri.port)

        if uri.scheme == 'https'
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE if settings['disable_ssl_validation']
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

        if user
          sync_user_names(user, user_data)
          sync_admin_status(user, user_data, settings)
        end

        user
      rescue => e
        Rails.logger.error "OIDC Bearer Exception: #{e.message}"
        nil
      end
    end

    # Decodes the JWT payload of a bearer token without verifying its signature.
    # Verification already happened at the userinfo endpoint; this only reads the
    # claims Keycloak put into the access token (e.g. `organization`).
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

    def sync_admin_status(user, user_data, settings)
      admin_group = settings['admin_group']
      return if admin_group.blank?

      user_groups = user_data['groups'] || []

      is_admin = user_groups.include?(admin_group)

      if user.admin != is_admin
        user.admin = is_admin
        user.save
        Rails.logger.info "OIDC Bearer: Updated admin status for #{user.login} to #{is_admin}"
      end
    end
  end
end