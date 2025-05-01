use crate::parse_btsnoop_file;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_one_nullstring_btletool_data_BTSnoopParser_log(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    text: jni::objects::JString,
) {
    let tag = env.new_string("BTSnoopParser").unwrap();
    // Get the Log class
    let log_class = env.find_class("android/util/Log").unwrap();

    // Call the Log.i method
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
pub unsafe extern "C" fn Java_one_nullstring_btletool_data_BTSnoopParser_parse(
    #[allow(unused_mut)] mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    file_bytes: jni::objects::JByteArray,
) -> jni::sys::jstring {
    let file_bytes = env.convert_byte_array(file_bytes).unwrap();
    let message = env.new_string("Hi from rust").unwrap();
    unsafe {
        let env2 = env.unsafe_clone();
        Java_one_nullstring_btletool_data_BTSnoopParser_log(env2, _class, message);
    }

    match parse_btsnoop_file(file_bytes) {
        Ok(parsed_file) => match serde_json::to_string(&parsed_file) {
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
        },
        Err(e) => {
            let error_msg = format!("Parse error: {}", e);
            match env.new_string(error_msg) {
                Ok(s) => s.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
    }
}
