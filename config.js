// Public Supabase settings. The publishable key is safe to expose in the browser:
// every table is protected by Row Level Security, and only users listed in the
// `admins` table can change anything (see public.is_admin()).
window.SITE_CONFIG = {
  url: "https://rflzxlzoimfshfvgqaxs.supabase.co",
  key: "sb_publishable_iq5yMlNxEYlhiK3jR0rjug_NDPzGCCW",
  bucket: "site-images",
  // Admin usernames are stored as Supabase Auth users with a placeholder email on this
  // reserved, undeliverable domain. Keep in sync with EMAIL_DOMAIN in the admin-users function.
  usernameDomain: "admin.bisianumu.invalid"
};

// "alice" -> "alice@admin.bisianumu.invalid"; a real email address is used as typed.
window.SITE_CONFIG.toLoginEmail = function (input) {
  const v = String(input || "").trim().toLowerCase();
  return v.indexOf("@") === -1 ? v + "@" + window.SITE_CONFIG.usernameDomain : v;
};
// The reverse, for display.
window.SITE_CONFIG.toDisplayName = function (email) {
  const suffix = "@" + window.SITE_CONFIG.usernameDomain;
  return email && email.endsWith(suffix) ? email.slice(0, -suffix.length) : (email || "");
};
