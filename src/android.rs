use crate::data::ATTCommand;
use crate::parse_btsnoop_file;
use jni::sys::{JNI_VERSION_1_6, jint};
use jni::{JNIEnv, NativeMethod};
use std::ffi::c_void;

#[unsafe(no_mangle)]
unsafe extern "system" fn log_impl(
    mut env: JNIEnv,
    _class: jni::objects::JClass,
    text: jni::objects::JString,
) {
    let tag = env.new_string("BTSnoopParser").unwrap();
    let log_class = env.find_class("android/util/Log").unwrap();

    env.call_static_method(
        log_class,
        "i",
        "(Ljava/lang/String;Ljava/lang/String;)I",
        &[
            jni::objects::JValue::Object(&tag),
            jni::objects::JValue::Object(&text),
        ],
    )
    .unwrap();
}

#[unsafe(no_mangle)]
unsafe extern "system" fn parse_impl(
    #[allow(unused_mut)] mut env: JNIEnv,
    _class: jni::objects::JClass,
    file_bytes: jni::objects::JByteArray,
    write_and_hvn_only: jni::sys::jboolean,
    sort_by_timestamp: jni::sys::jboolean,
) -> jni::sys::jstring {
    let file_bytes = env.convert_byte_array(file_bytes).unwrap();
    let message = env.new_string("Parsing Bluetooth Snoop File").unwrap();
    unsafe {
        let env2 = env.unsafe_clone();
        log_impl(env2, _class, message);
    }

    match parse_btsnoop_file(file_bytes) {
        Ok(mut parsed_file) => {
            if write_and_hvn_only == jni::sys::JNI_TRUE {
                parsed_file.packets.retain(|packet| {
                    packet.att_header.as_ref().map(|f| f.command) == Some(ATTCommand::WriteCommand)
                        || packet.att_header.as_ref().map(|f| f.command)
                            == Some(ATTCommand::HandleValueNotification)
                });
            }
            if sort_by_timestamp == jni::sys::JNI_TRUE {
                parsed_file
                    .packets
                    .sort_by_key(|packet| packet.header.timestamp_milliseconds);
            }
            match serde_json::to_string(&parsed_file) {
                Ok(json) => match env.new_string(json) {
                    Ok(j) => j.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                },
                Err(e) => {
                    let error_msg = format!("Serialization error: {}", e);
                    match env.new_string(error_msg) {
                        Ok(s) => s.into_raw(),
                        Err(_) => std::ptr::null_mut(),
                    }
                }
            }
        }
        Err(e) => {
            let error_msg = format!("Parse error: {}", e);
            match env.new_string(error_msg) {
                Ok(s) => s.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "system" fn JNI_OnLoad(vm: jni::JavaVM, _: c_void) -> jint {
    let mut env = match vm.get_env() {
        Ok(env) => env,
        Err(_) => return -1,
    };

    let class_name = "one/nullstring/btsnoop_parser/BTSnoopParser";
    let clazz = match env.find_class(class_name) {
        Ok(class) => class,
        Err(_) => return -1,
    };

    let methods = [
        NativeMethod {
            name: "log".into(),
            sig: "(Ljava/lang/String;)V".into(),
            fn_ptr: log_impl as *mut _,
        },
        NativeMethod {
            name: "parse".into(),
            sig: "([BZZ)Ljava/lang/String;".into(),
            fn_ptr: parse_impl as *mut _,
        },
    ];

    if let Err(_) = env.register_native_methods(clazz, &methods) {
        return -1;
    }

    JNI_VERSION_1_6 as jint
}
