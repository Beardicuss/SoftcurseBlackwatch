# Blackwatch v1.0 Navigation and Focus Flow

Blackwatch uses one persistent desktop shell. The focus flow is:

`Window controls → sidebar sections → active page controls/table → persistent Scan Now/Purge controls`

The sidebar exposes Dashboard, Threats, Processes, Network, Logs, and Settings as ordinary buttons. Tab and Shift+Tab follow document order. When focus is inside the sidebar, Arrow Up/Down wraps between sections, while Home and End select the first and last section. Selecting a section updates both the React view and native host state.

Tables remain native semantic tables. Process and log collections are split into bounded pages; Previous and Next remain in the normal tab sequence, expose disabled state natively, and announce the current page through a polite live region.

Native confirmation dialogs own focus during live-response, trust, and recovery consent. Returning from a dialog restores focus through WebView2's normal desktop behavior. Blackwatch has no browser-history navigation because its internal pages are application state rather than URLs.

The operating-system reduced-motion preference disables continuous CSS effects and instructs Framer Motion to replace transform animation with reduced-motion behavior. All buttons receive a consistent high-contrast focus indicator.
