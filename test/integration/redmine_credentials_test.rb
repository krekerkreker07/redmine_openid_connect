require File.expand_path('../../test_helper', __FILE__)

# SPR-546: only the Keycloak Bearer token signs a user in. Redmine's own credentials — the API
# key in its three forms, Basic with a password, the Atom feed key — are refused, and JSONP is
# off even where a tenant has it stored as enabled.
class RedmineCredentialsTest < Redmine::ApiTest::Base
  fixtures :users, :email_addresses, :members, :member_roles, :roles, :projects,
           :enabled_modules, :trackers, :projects_trackers, :issues, :issue_statuses,
           :enumerations, :tokens

  def setup
    super
    Setting.rest_api_enabled = '1'
    Setting.jsonp_enabled = '1'
    Setting.login_required = '0'
    @api_key = User.find(2).api_key
  end

  def test_the_api_key_header_is_refused
    get '/users/current.json', headers: { 'X-Redmine-API-Key' => @api_key }
    assert_response 401
  end

  def test_the_api_key_parameter_is_refused
    get "/users/current.json?key=#{@api_key}"
    assert_response 401
  end

  def test_basic_with_a_password_is_refused
    get '/users/current.json', headers: credentials('jsmith')
    assert_response 401
  end

  def test_basic_with_the_api_key_as_user_name_is_refused
    get '/users/current.json', headers: credentials(@api_key, 'X')
    assert_response 401
  end

  def test_the_atom_key_is_refused
    get "/issues.atom?key=#{User.find(2).atom_key}&project_id=onlinestore"
    assert_response 302
  end

  def test_a_bearer_token_still_signs_in
    ApplicationController.any_instance.stubs(:find_user_by_oidc_token).with('t0ken').returns(User.find(2))
    get '/users/current.json', headers: { 'Authorization' => 'Bearer t0ken' }
    assert_response 200
    assert_equal 'jsmith', response.parsed_body['user']['login']
  end

  # The SPA re-authenticates on 401 only; switching rest_api_enabled off would have made this 403.
  def test_an_api_request_without_a_user_is_still_401
    get '/users/current.json'
    assert_response 401
  end

  def test_jsonp_is_off_even_when_the_setting_is_on
    get '/projects.json?callback=cb'
    assert_response 200
    assert_equal 'application/json', response.media_type
    assert_not response.body.start_with?('cb(')
  end
end
