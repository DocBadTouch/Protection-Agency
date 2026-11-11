"""Small, version-specific snapshot; an addition to live advisories, not a feed."""
SOURCE = "https://www.sonatype.com/blog/polinrider-loader-reappears-in-hijacked-npm-packages"
REVIEWED = "2026-11-10"
# Exact releases from Sonatype Research Labs, 2026-11-04. No family-wide bans.
POLINRIDER_NPM = {
    "@adminide-stack/client-redux": {"0.0.16-18"},
    "@adminide-stack/health-api-server": {"0.0.18-alpha.465"},
    "@adminide-stack/user-activity-browser": {"1.1.3-alpha.114"},
    "@adminide-stack/utils": {"0.0.16-129", "0.0.16-130"},
    "server-hemera-mongo": {"0.0.15", "0.0.16"},
    "cdeops": {"13.5.31"},
    "@adminide-stack/forms-core": {"5.1.9-alpha.3"},
    "@adminide-stack/yantra-help-browser": {"12.0.194"},
    "@cdmbase/wiki-browser": {"12.0.18-alpha.53"},
    "@pubngo-stack/help-browser": {"12.0.23-alpha.3"},
}
POLINRIDER_WALLET = "0x1eef0849eda15d87f64e51c73c8442cf3c8bcef3"
