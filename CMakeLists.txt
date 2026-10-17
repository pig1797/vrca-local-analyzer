cmake_minimum_required(VERSION 3.20)
project(VrcaLocalAnalysis VERSION 0.1.0 LANGUAGES C CXX)

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

# Strict known-size LZMA1 decoder used only by writeback and its verifier.
add_library(vrca_lzma1ext SHARED native/src/vrca_lzma1ext.c)
target_include_directories(vrca_lzma1ext PRIVATE native/third_party/xz/include)
if(WIN32)
    set_target_properties(vrca_lzma1ext PROPERTIES PREFIX "")
endif()
if(NOT WIN32)
    find_package(LibLZMA REQUIRED)
    target_link_libraries(vrca_lzma1ext PRIVATE LibLZMA::LibLZMA)
endif()
add_custom_command(TARGET vrca_lzma1ext POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_SOURCE_DIR}/bin"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:vrca_lzma1ext>" "${CMAKE_SOURCE_DIR}/bin/")
install(TARGETS vrca_lzma1ext RUNTIME DESTINATION bin LIBRARY DESTINATION bin)

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
    add_test(NAME project_restore
        COMMAND "${Python3_EXECUTABLE}" -m unittest discover
            -s "${CMAKE_CURRENT_SOURCE_DIR}/tests" -p test_project_restore.py -v)
    set_tests_properties(project_restore PROPERTIES TIMEOUT 30)
    add_test(NAME writeback_codec
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_strict_lzma1ext.py")
    set_tests_properties(writeback_codec PROPERTIES TIMEOUT 60)
    add_test(NAME local_operations
        COMMAND "${Python3_EXECUTABLE}" -m unittest discover
            -s "${CMAKE_CURRENT_SOURCE_DIR}/tests" -p test_local_operations.py -v)
    set_tests_properties(local_operations PROPERTIES TIMEOUT 30)
endif()
