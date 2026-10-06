# CI ZAP startup failure and remediation

The original CI run 37102369547 authenticated successfully, confirmed five cross-user denials and passed 56 tests, SAST and the image vulnerability scan. ZAP then failed to exit within 1,200 seconds. The subprocess timeout discarded its captured console output, leaving no useful startup diagnostics.

Diagnostic run 37401792339 reproduced the stall with preserved, redacted logs. ZAP stopped during extension initialization, before any Automation Framework job began. Java could not create/lock user preferences and Selenium could not create `/home/zap/.cache/selenium`. The official image owns its default home as UID 1000, while the GitHub runner executes the scanner as UID 1001. The Firefox profile initializer also waits for its child process without a deadline; a non-writable default home prevented normal initialization.

The scanner now uses `/zap/wrk/zap-home`, within the existing writable bind mount, for both shell HOME and Java user.home. Java preferences and Selenium cache also live there. Firefox uses the executable already installed in the official image; Selenium is explicitly offline and does not send usage statistics. A container-side write probe verifies the home is writable under the actual UID before authenticating or starting ZAP. The scanner retains its non-root identity and internal-only network.

Compose launches without a TTY or interactive stdin. Deadlines default to 600 seconds for passive scans and 1,200 seconds for active scans. Timeout output and the internal startup log are redacted and saved, the manifest records failed coverage, and the named one-off container is removed. Old report files are cleared before execution so a previous report cannot make an incomplete scan appear successful. Security severity and missing-coverage gates remain enforced.

Regression tests cover byte-valued timeout output, preserved diagnostics, credential redaction, unauthorized targets and failed preflight coverage. The complete CI rerun is the acceptance check; see the repository's Actions tab for its result and artifacts.

References: [official ZAP Dockerfile](https://github.com/zaproxy/zaproxy/blob/main/docker/Dockerfile-stable), [Firefox profile initializer](https://github.com/zaproxy/zap-extensions/blob/main/addOns/selenium/src/main/java/org/zaproxy/zap/extension/selenium/internal/FirefoxProfileManager.java), [ZAP Selenium system properties](https://www.zaproxy.org/docs/desktop/addons/selenium/options/).
