module RedmineOpenidConnect
  # SPR-546: JSONP is off whatever the tenant's settings say. With it, `?callback=cb` wrapped any
  # API answer in executable JavaScript, which another site could load with a <script> tag.
  # Every tenant seeded before SPR-546 has `jsonp_enabled = 1` stored, so the stored value is
  # not trusted. Nothing of ours calls the API through JSONP.
  module SettingPatch
    def jsonp_enabled?
      false
    end
  end
end
