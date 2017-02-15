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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/param.h>
#include "asyncProfiler.h"
#include "vmEntry.h"

ASGCTType asgct;
Profiler Profiler::_instance;

static void sigprofHandler(int signo, siginfo_t* siginfo, void* ucontext) {
    Profiler::_instance.recordSample(ucontext);
}

MethodName::MethodName(jmethodID method) {
    jclass method_class;
    jvmtiEnv* jvmti = VM::jvmti();
    jvmti->GetMethodName(method, &_name, &_sig, NULL);
    jvmti->GetMethodDeclaringClass(method, &method_class);
    jvmti->GetClassSignature(method_class, &_class_sig, NULL);

    char* s;
    for (s = _class_sig; *s; s++) {
        if (*s == '/') *s = '.';
    }
    s[-1] = 0;
}

MethodName::~MethodName() {
    jvmtiEnv* jvmti = VM::jvmti();
    jvmti->Deallocate((unsigned char*)_name);
    jvmti->Deallocate((unsigned char*)_sig);
    jvmti->Deallocate((unsigned char*)_class_sig);
}

void Profiler::frameBufferSize(int size) {
    if (size >= 0) {
        _frameBufferSize = size;
    } else {
        std::cerr << "Ignoring frame buffer size " << size << std::endl;
    }
}

u64 Profiler::hashCallTrace(ASGCT_CallTrace* trace) {
    const u64 M = 0xc6a4a7935bd1e995LL;
    const int R = 47;

    u64 h = trace->num_frames * M;

    for (int i = 0; i < trace->num_frames; i++) {
        u64 k = (u64) trace->frames[i].method_id;
        k *= M;
        k ^= k >> R;
        k *= M;
        h ^= k;
        h *= M;
    }

    h ^= h >> R;
    h *= M;
    h ^= h >> R;

    return h;
}

void Profiler::storeCallTrace(ASGCT_CallTrace* trace) {
    u64 hash = hashCallTrace(trace);
    int bucket = (int)(hash % MAX_CALLTRACES);
    int i = bucket;

    do {
        if (_hashes[i] == hash && _traces[i]._call_count > 0) {
            _traces[i]._call_count++;
            return;
        } else if (_hashes[i] == 0) {
            break;
        }
        if (++i == MAX_CALLTRACES) i = 0;
    } while (i != bucket);
    
    if (_frameBufferSize - _freeFrame < trace->num_frames) {
        // Don't have enough space to store call trace
        _frameBufferOverflow = true;
        return;
    }

    _hashes[i] = hash;
    
    _traces[i]._call_count = 1;
    _traces[i]._offset = _freeFrame;
    _traces[i]._num_frames = trace->num_frames;

    // Copying frames into frame buffer
    for (int i = 0; i < trace->num_frames; i++) {
        _frames[_freeFrame] = trace->frames[i].method_id;
        _freeFrame++;
    }
}

u64 Profiler::hashMethod(jmethodID method) {
    const u64 M = 0xc6a4a7935bd1e995LL;
    const int R = 17;

    u64 h = (u64)method;

    h ^= h >> R;
    h *= M;
    h ^= h >> R;

    return h;
}

void Profiler::storeMethod(jmethodID method) {
    u64 hash = hashMethod(method);
    int bucket = (int)(hash % MAX_CALLTRACES);
    int i = bucket;

    do {
        if (_methods[i]._method == method) {
            _methods[i]._call_count++;
            return;
        } else if (_methods[i]._method == NULL) {
            break;
        }
        if (++i == MAX_CALLTRACES) i = 0;
    } while (i != bucket);

    _methods[i]._method = method;
    _methods[i]._call_count = 1;
}

void Profiler::checkDeadline() {
    if (time(NULL) > _deadline) {
        const char error[] = "Disabling profiler due to deadline\n";
        ssize_t w = write(STDERR_FILENO, error, sizeof(error) - 1);
        (void) w;

        _running = false;
        setTimer(0, 0);
    }
}

void Profiler::recordSample(void* ucontext) {
    checkDeadline();

    _calls_total++;

    JNIEnv* jni = VM::jni();
    if (jni == NULL) {
        _calls_non_java++;
        return;
    }

    const int FRAME_BUFFER_SIZE = 4096;
    ASGCT_CallFrame frames[FRAME_BUFFER_SIZE];
    ASGCT_CallTrace trace = {jni, FRAME_BUFFER_SIZE, frames};

    (*asgct)(&trace, trace.num_frames, ucontext);

    if (trace.num_frames > 0) {
        storeCallTrace(&trace);
        storeMethod(frames[0].method_id);
    } else {
        // See ticks_* enum values in
        // http://hg.openjdk.java.net/jdk8/jdk8/hotspot/file/tip/src/share/vm/prims/forte.cpp
        switch (trace.num_frames) {
            case  0: _calls_non_java++;              break;
            case -1: _calls_no_class_load++;         break;
            case -2: _calls_gc_active++;             break;
            case -3: _calls_unknown_not_java++;      break;
            case -4: _calls_not_walkable_not_java++; break;
            case -5: _calls_unknown_java++;          break;
            case -6: _calls_not_walkable_java++;     break;
            case -7: _calls_unknown_state++;         break;
            case -8: _calls_thread_exit++;           break;
            case -9: _calls_deopt++;                 break;
            default: _calls_unknown++;               break;
        }
    }
}

void Profiler::setTimer(long sec, long usec) {
    bool enabled = sec | usec;
    struct itimerval itv = {{sec, usec}, {sec, usec}};

    if (enabled) {
        struct sigaction sa;
        sigemptyset(&sa.sa_mask);
        sa.sa_handler = NULL;
        sa.sa_sigaction = sigprofHandler;
        sa.sa_flags = SA_RESTART | SA_SIGINFO;
        
        if (sigaction(SIGPROF, &sa, NULL) != 0)
            perror("couldn't install signal handler");

        if (setitimer(ITIMER_PROF, &itv, NULL) != 0)
            perror("couldn't start timer");
    } else {
        if (setitimer(ITIMER_PROF, &itv, NULL) != 0)
            perror("couldn't stop timer");
    }
}

void Profiler::start(int interval, int duration) {
    if (_running || interval <= 0 || duration <= 0) return;
    _running = true;

    _calls_total = 0;
    _calls_non_java = 0;
    _calls_no_class_load = 0;
    _calls_gc_active = 0;
    _calls_unknown_not_java = 0;
    _calls_not_walkable_not_java = 0;
    _calls_unknown_java = 0;
    _calls_not_walkable_java = 0;
    _calls_unknown_state = 0;
    _calls_thread_exit = 0;
    _calls_deopt = 0;
    _calls_safepoint = 0;
    _calls_unknown = 0;
    memset(_hashes, 0, sizeof(_hashes));
    memset(_traces, 0, sizeof(_traces));
    memset(_methods, 0, sizeof(_methods));

    // Reset frames
    free(_frames);
    _frames = (jmethodID *) malloc(_frameBufferSize * sizeof (jmethodID));
    _freeFrame = 0;
    _frameBufferOverflow = false;

    _deadline = time(NULL) + duration;

    setTimer(interval / 1000, (interval % 1000) * 1000);
}

void Profiler::stop() {
    if (!_running) return;
    _running = false;

    setTimer(0, 0);
    
    if (_frameBufferOverflow) {
        std::cerr << "Frame buffer overflowed with size " << _frameBufferSize
                << ". Consider increasing its size." << std::endl;
    } else {
        std::cout << "Frame buffer usage "
                << _freeFrame << "/" << _frameBufferSize
                << "="
                << 100.0 * _freeFrame / _frameBufferSize << "%" << std::endl;
    }
}

static void nonzero_summary(std::ostream& out, const char* title, int calls, float percent) {
    if (calls > 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%-20s %d (%.2f%%)\n", title, calls, calls * percent);
        out << buf;
    }
}

void Profiler::summary(std::ostream& out) {
    float percent = 100.0f / _calls_total;
    char buf[256];
    snprintf(buf, sizeof(buf),
            "--- Execution profile ---\n"
            "Total:               %d\n",
            _calls_total);
    out << buf;
    
    nonzero_summary(out, "No Java frame:",       _calls_non_java,              percent);
    nonzero_summary(out, "No class load:",       _calls_no_class_load,         percent);
    nonzero_summary(out, "GC active:",           _calls_gc_active,             percent);
    nonzero_summary(out, "Unknown (non-Java):",  _calls_unknown_not_java,      percent);
    nonzero_summary(out, "Not walkable (nonJ):", _calls_not_walkable_not_java, percent);
    nonzero_summary(out, "Unknown Java:",        _calls_unknown_java,          percent);
    nonzero_summary(out, "Not walkable (Java):", _calls_not_walkable_java,     percent);
    nonzero_summary(out, "Unknown state:",       _calls_unknown_state,         percent);
    nonzero_summary(out, "Thread exit:",         _calls_thread_exit,           percent);
    nonzero_summary(out, "Deopt:",               _calls_deopt,                 percent);
    nonzero_summary(out, "Safepoint:",           _calls_safepoint,             percent);
    nonzero_summary(out, "Unknown:",             _calls_unknown,               percent);

    out << std::endl;
}

/*
 * Dumping in lightweight-java-profiler format:
 * 
 * <samples> <frames>   <frame1>
 *                      <frame2>
 *                      ...
 *                      <framen>
 * ...
 * Total ...
 */
void Profiler::dumpRawTraces(std::ostream& out) {
    if (_running) return;

    for (int i = 0; i < MAX_CALLTRACES; i++) {
        const int samples = _traces[i]._call_count;
        if (samples == 0) continue;
        
        out << samples << '\t' << _traces[i]._num_frames << '\t';

        CallTraceSample& trace = _traces[i];
        for (int j = 0; j < trace._num_frames; j++) {
            jmethodID method = _frames[trace._offset + j];
            if (method != NULL) {
                if (j != 0) {
                    out << "\t\t";
                }

                MethodName mn(method);
                out << mn.holder() << "::" << mn.name() << std::endl;
            }
        }
    }
    
    out << "Total" << std::endl;
}

void Profiler::dumpTraces(std::ostream& out, int max_traces) {
    CallTraceSample *traces;
    CallTraceSample *snapshot_traces = NULL;

    if (!_running) {
        traces = _traces;
    } else {
        snapshot_traces = new CallTraceSample[MAX_CALLTRACES];
        memcpy(snapshot_traces, _traces, sizeof(_traces));
        traces = snapshot_traces;
    }    

    float percent = 100.0f / _calls_total;
    char buf[1024];

    qsort(traces, MAX_CALLTRACES, sizeof(CallTraceSample), CallTraceSample::comparator);
    if (max_traces > MAX_CALLTRACES) max_traces = MAX_CALLTRACES;

    for (int i = 0; i < max_traces; i++) {
        int samples = traces[i]._call_count;
        if (samples == 0) break;

        snprintf(buf, sizeof(buf), "Samples: %d (%.2f%%)\n", samples, samples * percent);
        out << buf;

        CallTraceSample& trace = traces[i];
        for (int j = 0; j < trace._num_frames; j++) {
            jmethodID method = _frames[trace._offset + j];
            if (method != NULL) {
                MethodName mn(method);
                snprintf(buf, sizeof(buf), "  [%2d] %s.%s\n", j, mn.holder(), mn.name());
                out << buf;
            }
        }
        out << "\n";
    }

    if (snapshot_traces != NULL) {
        free(snapshot_traces);
    }
}

void Profiler::dumpMethods(std::ostream& out) {
    MethodSample *methods;
    MethodSample *snapshot_methods = NULL;

    if (!_running) {
        methods = _methods;
    } else {
        snapshot_methods = new MethodSample[MAX_CALLTRACES];
        memcpy(snapshot_methods, _methods, sizeof(_methods));
        methods = snapshot_methods;
    }    

    float percent = 100.0f / _calls_total;
    char buf[1024];

    qsort(methods, MAX_CALLTRACES, sizeof(MethodSample), MethodSample::comparator);

    for (int i = 0; i < MAX_CALLTRACES; i++) {
        int samples = methods[i]._call_count;
        if (samples == 0 || methods[i]._method == NULL) break;

        MethodName mn(methods[i]._method);
        snprintf(buf, sizeof(buf), "%6d (%.2f%%) %s.%s\n", samples, samples * percent, mn.holder(), mn.name());
        out << buf;
    }

    if (snapshot_methods != NULL) {
        free(snapshot_methods);
    }
}
