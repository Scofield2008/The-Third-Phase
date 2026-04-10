TRACKER_SIGNATURES = {
    "com.facebook.ads":              "Facebook Audience Network (Ad tracking)",
    "com.facebook.analytics":        "Facebook Analytics",
    "com.google.firebase.analytics": "Google Firebase Analytics",
    "com.google.android.gms.ads":    "Google AdMob",
    "com.google.android.gms.analytics": "Google Analytics (legacy)",
    "com.appsflyer":                 "AppsFlyer (Attribution & analytics)",
    "io.branch.referral":            "Branch.io (Deep link tracking)",
    "com.amplitude.api":             "Amplitude Analytics",
    "com.mixpanel.android":          "Mixpanel Analytics",
    "com.segment.analytics":         "Segment Analytics",
    "com.crashlytics":               "Crashlytics / Firebase Crashlytics",
    "io.sentry":                     "Sentry (Error tracking)",
    "com.onesignal":                 "OneSignal (Push notifications)",
    "com.clevertap.android":         "CleverTap (Marketing analytics)",
    "com.chartboost":                "Chartboost (Ad SDK)",
    "com.unity3d.ads":               "Unity Ads",
    "com.ironsource.mediationsdk":   "IronSource (Ad mediation)",
    "com.applovin":                  "AppLovin (Ad network)",
    "com.mopub":                     "MoPub (Twitter ad SDK)",
    "com.twitter.sdk":               "Twitter SDK",
    "com.snapchat.sdk":              "Snapchat SDK",
    "com.tiktok.open.api":           "TikTok SDK",
    "com.adjust.sdk":                "Adjust (Attribution tracking)",
    "com.kochava.base":              "Kochava (Attribution tracking)",
    "com.singular.sdk":              "Singular (Attribution tracking)",
    "com.flurry.android":            "Yahoo Flurry Analytics",
    "com.comscore":                  "comScore (Audience measurement)",
    "com.localytics":                "Localytics Analytics",
    "com.newrelic.agent":            "New Relic (Performance monitoring)",
    "com.datadog.android":           "Datadog (Monitoring)",
    "com.intercom.android":          "Intercom (Customer messaging)",
    "com.zendesk":                   "Zendesk SDK",
    "com.braze":                     "Braze (formerly Appboy) marketing",
    "com.leanplum":                  "Leanplum (A/B testing & analytics)",
    "ai.the trade desk":             "The Trade Desk (Ad buying)",
    "com.moat.analytics":            "Moat Analytics (Oracle)",
    "com.doubleclick":               "DoubleClick (Google ad tracking)",
    "net.hockeyapp.android":         "HockeyApp (Microsoft crash reporting)",
    "com.bugsnag.android":           "Bugsnag (Error monitoring)",
    "com.instabug.library":          "Instabug (Bug reporting)",
}


def scan_classes_for_trackers(class_list):
    """
    Takes a list of Java class name strings from APK bytecode,
    returns a list of (package_path, tracker_name) tuples.
    """
    findings = []
    detected = set()

    for cls in class_list:
        cls_clean = cls.replace("/", ".").lstrip("L").rstrip(";")
        for signature, label in TRACKER_SIGNATURES.items():
            if cls_clean.startswith(signature):
                if signature not in detected:
                    detected.add(signature)
                    findings.append((signature, label))
    return findings