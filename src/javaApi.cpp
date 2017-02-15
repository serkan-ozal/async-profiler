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

#include <sstream>
#include "asyncProfiler.h"

extern "C" JNIEXPORT void JNICALL
Java_com_opsgenie_profile_AsyncProfiler_start(JNIEnv* env, jclass clazz, jint interval) {
    Profiler::_instance.start(interval ? interval : DEFAULT_INTERVAL);
}

extern "C" JNIEXPORT void JNICALL
Java_com_opsgenie_profile_AsyncProfiler_stop(JNIEnv* env, jclass clazz) {
    Profiler::_instance.stop();
}

extern "C" JNIEXPORT jint JNICALL
Java_com_opsgenie_profile_AsyncProfiler_getSamples(JNIEnv* env, jclass clazz) {
    return Profiler::_instance.samples();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_opsgenie_profile_AsyncProfiler_dumpTraces(JNIEnv* env, jclass clazz, jint max_traces) {
    std::ostringstream out;
    Profiler::_instance.summary(out);
    Profiler::_instance.dumpTraces(out, max_traces ? max_traces : DEFAULT_TRACES_TO_DUMP);
    return env->NewStringUTF(out.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_opsgenie_profile_AsyncProfiler_dumpMethods(JNIEnv* env, jclass clazz) {
    std::ostringstream out;
    Profiler::_instance.summary(out);
    Profiler::_instance.dumpMethods(out);
    return env->NewStringUTF(out.str().c_str());
}
