require File.expand_path('../../test_helper', __FILE__)

# SPR-554: every call to the Identity provider verifies its TLS certificate. The plugin used to
# offer a `disable_ssl_validation` setting that turned verification off (VERIFY_NONE for bearer
# tokens, and a process-wide `verify: false` for every HTTParty call); a value of it left in the
# database must not bring that back.
class TlsVerificationTest < ActiveSupport::TestCase
  fixtures :users, :email_addresses

  def setup
    @previous_settings = Setting.plugin_redmine_openid_connect
    @previous_httparty_verify = HTTParty::Basement.default_options[:verify]
    @previous_env = ENV['KEYCLOAK_ORG_ALIAS']
    ENV.delete('KEYCLOAK_ORG_ALIAS')
    Setting.plugin_redmine_openid_connect = {
      'enabled' => 'true',
      'client_id' => 'tracker-api',
      'client_secret' => 'secret',
      'openid_connect_server_url' => 'https://identity.example.test/auth/realms/sprintly',
      'disable_ssl_validation' => 'true'
    }
    OicSession.instance_variable_set(:@dynamic_config, {
      'token_endpoint' => 'https://identity.example.test/token',
      'userinfo_endpoint' => 'https://identity.example.test/userinfo'
    })
  end

  def teardown
    Setting.plugin_redmine_openid_connect = @previous_settings
    OicSession.instance_variable_set(:@dynamic_config, nil)
    if @previous_httparty_verify.nil?
      HTTParty::Basement.default_options.delete(:verify)
    else
      HTTParty::Basement.default_options[:verify] = @previous_httparty_verify
    end
    ENV['KEYCLOAK_ORG_ALIAS'] = @previous_env
  end

  def userinfo_response(body)
    response = Net::HTTPOK.new('1.1', '200', 'OK')
    response.instance_variable_set(:@read, true)
    response.instance_variable_set(:@body, body.to_json)
    response
  end

  def test_bearer_userinfo_call_verifies_the_certificate_even_with_the_legacy_setting
    http = Net::HTTP.new('identity.example.test', 443)
    Net::HTTP.stubs(:new).returns(http)
    http.stubs(:request).returns(userinfo_response('email' => 'jsmith@somenet.foo'))

    user = ApplicationController.new.send(:find_user_by_oidc_token, 'header.payload.signature')

    assert_equal 'jsmith', user&.login
    assert http.use_ssl?
    assert_equal OpenSSL::SSL::VERIFY_PEER, http.verify_mode
  end

  def test_token_and_userinfo_calls_leave_httparty_verification_on
    HTTParty.stubs(:post).returns({ 'error' => 'invalid_grant' })
    HTTParty.stubs(:get).returns(stub(headers: {}, body: '{}'))

    OicSession.get_token('grant_type' => 'refresh_token')
    OicSession.new(access_token: 'a.b.c').get_user_info!

    assert_not_equal false, HTTParty::Basement.default_options[:verify]
  end

  def test_dynamic_config_fetch_leaves_httparty_verification_on
    OicSession.instance_variable_set(:@dynamic_config, nil)
    HTTParty.stubs(:get).returns({ 'issuer' => 'https://identity.example.test/auth/realms/sprintly' })

    Rails.cache.clear
    OicSession.get_dynamic_config

    assert_not_equal false, HTTParty::Basement.default_options[:verify]
  end

  def test_the_settings_page_no_longer_offers_the_option
    view = File.read(File.expand_path('../../../app/views/settings/_redmine_openid_connect_settings.html.erb', __FILE__))
    assert_not_includes view, 'disable_ssl_validation'
  end
end
