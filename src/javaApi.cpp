/*
 * Copyright 2016 Andrei Pangin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Modified by Serkan ÖZAL on 15/02/2017
// Modified by Serkan ÖZAL on 24/02/2018

#include <sstream>
#include "asyncProfiler.h"

extern "C" JNIEXPORT jlong JNICALL
Java_com_opsgenie_thundra_profile_AsyncProfiler_getThreadProfilerId(JNIEnv* env, jclass clazz) {
    return (long) Profiler::_instance.getThreadProfilerId();
}

extern "C" JNIEXPORT void JNICALL
Java_com_opsgenie_thundra_profile_AsyncProfiler_start0(JNIEnv* env, jclass clazz, jint interval, jint duration) {
    Profiler::_instance.start(interval ? interval : DEFAULT_INTERVAL, duration ? duration : DEFAULT_DURATION);
}

extern "C" JNIEXPORT void JNICALL
Java_com_opsgenie_thundra_profile_AsyncProfiler_stop0(JNIEnv* env, jclass clazz) {
    Profiler::_instance.stop();
}

extern "C" JNIEXPORT jint JNICALL
Java_com_opsgenie_thundra_profile_AsyncProfiler_getSamples(JNIEnv* env, jclass clazz) {
    return Profiler::_instance.samples();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_opsgenie_thundra_profile_AsyncProfiler_dumpRawTraces(JNIEnv* env, jclass clazz, jint max_traces) {
    std::ostringstream out;
    Profiler::_instance.summary(out);
    Profiler::_instance.dumpRawTraces(out, max_traces);
    return env->NewStringUTF(out.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_opsgenie_thundra_profile_AsyncProfiler_dumpTraces(JNIEnv* env, jclass clazz, jint max_traces, jlong thread_profiler_id) {
    std::ostringstream out;
    Profiler::_instance.summary(out);
    Profiler::_instance.dumpTraces(out, max_traces ? max_traces : DEFAULT_TRACES_TO_DUMP, thread_profiler_id);
    return env->NewStringUTF(out.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_opsgenie_thundra_profile_AsyncProfiler_dumpMethods(JNIEnv* env, jclass clazz, jint max_traces) {
    std::ostringstream out;
    Profiler::_instance.summary(out);
    Profiler::_instance.dumpMethods(out, max_traces);
    return env->NewStringUTF(out.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_opsgenie_thundra_profile_AsyncProfiler_dumpFlameGraph(JNIEnv* env, jclass clazz, jint max_traces) {
    std::ostringstream out;
    Profiler::_instance.dumpFlameGraph(out, max_traces);
    return env->NewStringUTF(out.str().c_str());
}
