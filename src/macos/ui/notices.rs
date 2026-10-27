// The notices of the app in the Notification Center, as the balloons on Windows; a click on one is a click on the
// balloon. macOS asks the user once whether the app can show them. Only an app in its bundle has them: the tests
// write them in the log.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{Bool, ProtocolObject};
use objc2::{define_class, msg_send, AnyThread};
use objc2_foundation::{NSBundle, NSError, NSObject, NSObjectProtocol};
use objc2_user_notifications::{
    UNAuthorizationOptions, UNMutableNotificationContent, UNNotification, UNNotificationPresentationOptions,
    UNNotificationRequest, UNNotificationResponse, UNUserNotificationCenter, UNUserNotificationCenterDelegate,
};

use super::{later, ns, with_app};
use crate::log;

static AVAILABLE: AtomicBool = AtomicBool::new(false);
static NEXT: AtomicU64 = AtomicU64::new(1);

define_class!(
    // the center calls it on a thread of its own
    #[unsafe(super(NSObject))]
    #[name = "AuthwayNotices"]
    struct Delegate;

    unsafe impl NSObjectProtocol for Delegate {}

    unsafe impl UNUserNotificationCenterDelegate for Delegate {
        // also while a window of the app is in front
        #[unsafe(method(userNotificationCenter:willPresentNotification:withCompletionHandler:))]
        fn will_present(
            &self,
            _center: &UNUserNotificationCenter,
            _notification: &UNNotification,
            handler: &block2::DynBlock<dyn Fn(UNNotificationPresentationOptions)>,
        ) {
            handler.call((UNNotificationPresentationOptions::Banner | UNNotificationPresentationOptions::List,));
        }

        #[unsafe(method(userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:))]
        fn did_receive(
            &self,
            _center: &UNUserNotificationCenter,
            _response: &UNNotificationResponse,
            handler: &block2::DynBlock<dyn Fn()>,
        ) {
            later(|| {
                with_app(|app| app.balloon_clicked());
            });
            handler.call(());
        }
    }
);

fn center() -> Option<Retained<UNUserNotificationCenter>> {
    AVAILABLE.load(Ordering::SeqCst).then(UNUserNotificationCenter::currentNotificationCenter)
}

pub fn setup() {
    // without a bundle, the center ends the process
    if NSBundle::mainBundle().bundleIdentifier().is_none() {
        return;
    }
    AVAILABLE.store(true, Ordering::SeqCst);
    let Some(center) = center() else { return };
    let delegate: Retained<Delegate> = unsafe { msg_send![Delegate::alloc(), init] };
    center.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    // the center doesn't keep it
    std::mem::forget(delegate);
    let answered = RcBlock::new(|granted: Bool, _error: *mut NSError| {
        if !granted.as_bool() {
            log!("the notices of the app are off in the settings of macOS");
        }
    });
    center.requestAuthorizationWithOptions_completionHandler(
        UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
        &answered,
    );
}

pub fn post(text: &str, warning: bool) {
    let Some(center) = center() else {
        log!("notice: {}", text);
        return;
    };
    let content = UNMutableNotificationContent::new();
    content.setTitle(&ns(crate::names::PRODUCT));
    content.setBody(&ns(text));
    if warning {
        content.setSound(Some(&objc2_user_notifications::UNNotificationSound::defaultSound()));
    }
    let identifier = ns(&format!("notice-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    let request = UNNotificationRequest::requestWithIdentifier_content_trigger(&identifier, &content, None);
    center.addNotificationRequest_withCompletionHandler(&request, None);
}
