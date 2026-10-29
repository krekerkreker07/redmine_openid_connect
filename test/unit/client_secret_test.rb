require File.expand_path('../../test_helper', __FILE__)

class ClientSecretTest < ActiveSupport::TestCase
  def setup
    @previous_settings = Setting.plugin_redmine_openid_connect
    @previous_env = ENV['OIDC_CLIENT_SECRET']
    Setting.plugin_redmine_openid_connect = { 'client_id' => 'tracker-api', 'client_secret' => 'from-settings' }
  end

  def teardown
    Setting.plugin_redmine_openid_connect = @previous_settings
    ENV['OIDC_CLIENT_SECRET'] = @previous_env
  end

  def test_the_environment_wins_over_the_settings
    ENV['OIDC_CLIENT_SECRET'] = 'from-env'
    assert_equal 'from-env', OicSession.client_secret
  end

  def test_the_settings_are_used_when_the_environment_is_unset
    ENV.delete('OIDC_CLIENT_SECRET')
    assert_equal 'from-settings', OicSession.client_secret
  end

  def test_a_blank_environment_value_counts_as_unset
    ENV['OIDC_CLIENT_SECRET'] = ''
    assert_equal 'from-settings', OicSession.client_secret
  end

  def test_the_token_request_authenticates_with_that_secret
    ENV['OIDC_CLIENT_SECRET'] = 'from-env'
    OicSession.stubs(:dynamic_config).returns('token_endpoint' => 'https://identity.example.test/token')
    HTTParty.expects(:post).with do |_uri, options|
      options[:basic_auth] == { username: 'tracker-api', password: 'from-env' }
    end.returns({})
    OicSession.get_token({})
  end
end
