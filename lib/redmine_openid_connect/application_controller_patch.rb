module RedmineOpenidConnect
  module ApplicationControllerPatch
    def find_current_user
      user = super
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
        email = user_data['email']
        return nil if email.blank?

        user = User.find_by_mail(email)

        if user.nil? && settings['create_user_if_not_exists']
          user = create_user_from_oidc(user_data)
        end

        if user
          sync_admin_status(user, user_data, settings)
        end

        user
      rescue => e
        Rails.logger.error "OIDC Bearer Exception: #{e.message}"
        nil
      end
    end

    def create_user_from_oidc(user_data)
      user = User.new
      user.login = user_data['preferred_username'] || user_data['email']
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