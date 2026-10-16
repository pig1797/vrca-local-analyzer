cmake_minimum_required(VERSION 3.20)
project(VrcaLocalAnalysis VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# A portable worker must not depend on a separately installed VC++ runtime.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(vrc_analysis STATIC
    native/src/server_plan_scope.cpp
    native/src/server_common.cpp
    native/src/server_rule_profile.cpp
    native/src/mini_json.cpp
    native/src/analysis.cpp
    native/src/menu_condition_proof.cpp
    native/src/avacrypt_v1_solver.cpp)
target_include_directories(vrc_analysis PUBLIC native/src)
# This build selects the portable, local rules: no card server, licence client,
# proprietary SDK, signed rule download, or optional research solver.
target_compile_definitions(vrc_analysis PUBLIC
    VRC_SERVER_WORKER=1 NDEBUG=1 VRC_SERVER_POLICY_BUILD=45)
if(MSVC)
    target_compile_options(vrc_analysis PRIVATE /W4 /utf-8)
else()
    target_compile_options(vrc_analysis PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(VrcAnalysisWorker native/src/server_worker_main.cpp)
target_link_libraries(VrcAnalysisWorker PRIVATE vrc_analysis)
if(MSVC)
    # MSVC's 1 MiB default overflows (0xc00000fd) even on the small synthetic
    # graph suite because of the compiled analysis frame. Use one fixed 8 MiB
    # reserve, matching the usual Linux main-thread budget; no unbounded growth.
    target_link_options(VrcAnalysisWorker PRIVATE /STACK:8388608)
endif()
if(MINGW)
    target_link_options(VrcAnalysisWorker PRIVATE -municode -static)
endif()
install(TARGETS VrcAnalysisWorker RUNTIME DESTINATION bin)

if(WIN32)
    add_executable(VrcaLocalLauncher WIN32 native/src/local_launcher.cpp)
    target_link_libraries(VrcaLocalLauncher PRIVATE user32)
    if(MSVC)
        target_compile_options(VrcaLocalLauncher PRIVATE /utf-8)
    elseif(MINGW)
        target_link_options(VrcaLocalLauncher PRIVATE -municode -static)
    endif()
endif()

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 3.10 COMPONENTS Interpreter REQUIRED)
    add_test(NAME contact_confidence
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_contact_guard_password_confidence.py"
            "$<TARGET_FILE:VrcAnalysisWorker>")
    set_tests_properties(contact_confidence PROPERTIES TIMEOUT 120)
    add_test(NAME local_launcher
        COMMAND "${Python3_EXECUTABLE}" -m unittest discover
            -s "${CMAKE_CURRENT_SOURCE_DIR}/tests" -p test_local_launcher.py -v)
    set_tests_properties(local_launcher PROPERTIES TIMEOUT 30)
    add_test(NAME worker_interface
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_worker_interface.py"
            "$<TARGET_FILE:VrcAnalysisWorker>")
    set_tests_properties(worker_interface PROPERTIES TIMEOUT 30)
    add_test(NAME local_web
        COMMAND "${Python3_EXECUTABLE}" -m unittest discover
            -s "${CMAKE_CURRENT_SOURCE_DIR}/tests" -p test_local_web.py -v)
    set_tests_properties(local_web PROPERTIES TIMEOUT 60)
endif()
