require File.expand_path('../../test_helper', __FILE__)

class OicSessionTest < ActiveSupport::TestCase

  def setup
    @previous_settings = Setting.plugin_redmine_openid_connect
    @previous_env = ENV['KEYCLOAK_ORG_ALIAS']
    ENV.delete('KEYCLOAK_ORG_ALIAS')
  end

  def teardown
    Setting.plugin_redmine_openid_connect = @previous_settings
    ENV['KEYCLOAK_ORG_ALIAS'] = @previous_env
  end

  def configure_organization(value)
    Setting.plugin_redmine_openid_connect = { 'organization' => value }
  end

  # --- organization_aliases: every shape Keycloak may emit ------------------

  def test_organization_aliases_from_plain_list
    assert_equal ['acme'], OicSession.organization_aliases('organization' => ['acme'])
  end

  def test_organization_aliases_from_attribute_map
    claims = { 'organization' => { 'acme' => { 'id' => 'uuid' } } }
    assert_equal ['acme'], OicSession.organization_aliases(claims)
  end

  def test_organization_aliases_from_list_of_objects
    claims = { 'organization' => [{ 'alias' => 'acme', 'id' => 'uuid' }] }
    assert_equal ['acme'], OicSession.organization_aliases(claims)
  end

  def test_organization_aliases_from_single_string
    assert_equal ['acme'], OicSession.organization_aliases('organization' => 'acme')
  end

  def test_organization_aliases_without_claim
    assert_equal [], OicSession.organization_aliases('email' => 'user@example.com')
    assert_equal [], OicSession.organization_aliases(nil)
  end

  # --- organization_member? -------------------------------------------------

  def test_membership_not_enforced_when_alias_blank
    configure_organization('')
    assert_equal false, OicSession.organization_enforced?
    assert OicSession.organization_member?('organization' => ['other'])
    assert OicSession.organization_member?(nil)
  end

  def test_member_of_configured_organization
    configure_organization('acme')
    assert OicSession.organization_member?('organization' => ['acme'])
  end

  def test_member_check_is_case_insensitive
    configure_organization('Acme')
    assert OicSession.organization_member?('organization' => ['ACME'])
  end

  def test_member_of_another_organization_is_refused
    configure_organization('acme')
    assert_equal false, OicSession.organization_member?('organization' => ['globex'])
  end

  def test_missing_claim_is_refused_when_enforced
    configure_organization('acme')
    assert_equal false, OicSession.organization_member?('email' => 'user@example.com')
  end

  def test_any_claim_source_may_carry_the_membership
    configure_organization('acme')
    # access token without the claim, userinfo response with it
    assert OicSession.organization_member?({ 'email' => 'user@example.com' },
                                           { 'organization' => ['acme'] })
  end

  def test_alias_falls_back_to_environment
    Setting.plugin_redmine_openid_connect = {}
    ENV['KEYCLOAK_ORG_ALIAS'] = 'acme'
    assert_equal 'acme', OicSession.organization_alias
    assert OicSession.organization_member?('organization' => ['acme'])
    assert_equal false, OicSession.organization_member?('organization' => ['globex'])
  end
end
