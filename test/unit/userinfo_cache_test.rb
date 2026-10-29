require File.expand_path('../../test_helper', __FILE__)

# SPR-561: a bearer token is checked with Keycloak's userinfo once, and the answer is reused for
# the token's remaining lifetime (at most five minutes) instead of a round trip per request.
class UserinfoCacheTest < ActiveSupport::TestCase
  fixtures :users, :email_addresses

  def setup
    @previous_settings = Setting.plugin_redmine_openid_connect
    @previous_env = ENV['KEYCLOAK_ORG_ALIAS']
    ENV.delete('KEYCLOAK_ORG_ALIAS')
    Setting.plugin_redmine_openid_connect = {
      'enabled' => 'true',
      'client_id' => 'tracker-api',
      'client_secret' => 'secret',
      'openid_connect_server_url' => 'https://identity.example.test/auth/realms/sprintly'
    }
    @store = ActiveSupport::Cache::MemoryStore.new
    Rails.stubs(:cache).returns(@store)
    @http = Net::HTTP.new('identity.example.test', 443)
    Net::HTTP.stubs(:new).returns(@http)
  end

  def teardown
    Setting.plugin_redmine_openid_connect = @previous_settings
    ENV['KEYCLOAK_ORG_ALIAS'] = @previous_env
  end

  def token(claims)
    encode = ->(part) { Base64.urlsafe_encode64(part.to_json, padding: false) }
    "#{encode.call('alg' => 'RS256')}.#{encode.call(claims)}.signature"
  end

  def response(code, body)
    klass = code == '200' ? Net::HTTPOK : Net::HTTPUnauthorized
    response = klass.new('1.1', code, 'msg')
    response.instance_variable_set(:@read, true)
    response.instance_variable_set(:@body, body.to_json)
    response
  end

  def authenticate(bearer)
    ApplicationController.new.send(:find_user_by_oidc_token, bearer)
  end

  def test_a_token_is_checked_with_keycloak_once_while_it_lives
    bearer = token('exp' => Time.now.to_i + 240, 'email' => 'jsmith@somenet.foo')
    @http.expects(:request).once.returns(response('200', 'email' => 'jsmith@somenet.foo'))

    assert_equal 'jsmith', authenticate(bearer)&.login
    assert_equal 'jsmith', authenticate(bearer)&.login
  end

  def test_each_token_has_its_own_entry
    first = token('exp' => Time.now.to_i + 240, 'sid' => 'a')
    second = token('exp' => Time.now.to_i + 240, 'sid' => 'b')
    @http.expects(:request).twice.returns(
      response('200', 'email' => 'jsmith@somenet.foo'),
      response('200', 'email' => 'dlopper@somenet.foo')
    )

    assert_equal 'jsmith', authenticate(first)&.login
    assert_equal 'dlopper', authenticate(second)&.login
    assert_equal 'jsmith', authenticate(first)&.login
  end

  def test_a_rejected_token_is_not_remembered
    bearer = token('exp' => Time.now.to_i + 240)
    @http.expects(:request).twice.returns(response('401', 'error' => 'invalid_token'))

    assert_nil authenticate(bearer)
    assert_nil authenticate(bearer)
  end

  def test_an_expired_or_undated_token_is_always_asked_about
    expired = token('exp' => Time.now.to_i - 5)
    undated = 'header.payload.signature'
    @http.expects(:request).times(4).returns(response('200', 'email' => 'jsmith@somenet.foo'))

    2.times { authenticate(expired) }
    2.times { authenticate(undated) }
  end

  def test_the_answer_is_kept_no_longer_than_five_minutes
    bearer = token('exp' => Time.now.to_i + 3600)
    @http.stubs(:request).returns(response('200', 'email' => 'jsmith@somenet.foo'))
    @store.expects(:write).with(anything, anything, expires_in: 300)

    authenticate(bearer)
  end

  def test_a_cached_answer_still_goes_through_the_organization_check
    ENV['KEYCLOAK_ORG_ALIAS'] = 'acme'
    bearer = token('exp' => Time.now.to_i + 240, 'organization' => ['other'])
    @http.expects(:request).once.returns(response('200', 'email' => 'jsmith@somenet.foo'))

    assert_nil authenticate(bearer)
    assert_nil authenticate(bearer)
  end
end
