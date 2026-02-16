# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT
#
# SetupBoostHeaders.cmake
#
# Ensures Boost::headers is defined.
# Uses an existing BOOST_HEADERS_DIR if defined,
# otherwise searches typical NuGet layouts (MSVC) or system paths (non-MSVC).

function(find_boost_headers_dir OUTVAR PKGROOT)
  file(GLOB _candidates
    "${PKGROOT}/boost/lib/native/include"
    "${PKGROOT}/boost.*/lib/native/include"
    "${PKGROOT}/boost/include"
    "${PKGROOT}/boost.*/include"
  )
  set(_found "")
  foreach (d IN LISTS _candidates)
    if (EXISTS "${d}/boost/version.hpp")
      set(_found "${d}")
      break()
    endif ()
  endforeach ()
  set(${OUTVAR} "${_found}" PARENT_SCOPE)
endfunction()

if (NOT TARGET Boost::headers)
  if (MSVC)
    set(_pkgroot "${CMAKE_BINARY_DIR}/packages")

    if (NOT DEFINED BOOST_HEADERS_DIR OR NOT EXISTS "${BOOST_HEADERS_DIR}/boost/version.hpp")
      find_boost_headers_dir(_boost_inc "${_pkgroot}")
      if (_boost_inc STREQUAL "")
        find_program(NUGET nuget REQUIRED)
        set(BOOST_VERSION "1.87.0")
        file(MAKE_DIRECTORY "${_pkgroot}")
        execute_process(
          COMMAND "${NUGET}" install boost -Version ${BOOST_VERSION} -ExcludeVersion -OutputDirectory "${_pkgroot}"
          RESULT_VARIABLE _res
        )
        if (NOT _res EQUAL 0)
          message(FATAL_ERROR "NuGet Boost headers install failed (exit ${_res}).")
        endif ()
        find_boost_headers_dir(_boost_inc "${_pkgroot}")
        if (_boost_inc STREQUAL "")
          message(FATAL_ERROR "Could not locate Boost headers under ${_pkgroot}")
        endif ()
      endif ()
      set(BOOST_HEADERS_DIR "${_boost_inc}" CACHE PATH "Path to Boost headers")
    endif ()

    add_library(Boost::headers INTERFACE IMPORTED)
    target_include_directories(Boost::headers INTERFACE "${BOOST_HEADERS_DIR}")

    if (EXISTS "${BOOST_HEADERS_DIR}/boost/version.hpp")
      file(STRINGS "${BOOST_HEADERS_DIR}/boost/version.hpp" _ver_line REGEX "#define BOOST_LIB_VERSION")
      string(REGEX REPLACE ".*\"([0-9_]+)\".*" "\\1" _boost_ver "${_ver_line}")
      message(STATUS "Boost headers: ${_boost_ver} at ${BOOST_HEADERS_DIR}")
    endif ()
  else()
    # Non-MSVC platforms (Linux/macOS): headers-only Boost
    find_path(BOOST_HEADERS_DIR
      NAMES boost/version.hpp
      PATHS /opt/homebrew/include /usr/local/include /usr/include
    )
    
    if (NOT BOOST_HEADERS_DIR)
      message(FATAL_ERROR "Boost headers not found. Please install boost (e.g., 'brew install boost' or 'apt install libboost-dev').")
    endif()

    add_library(Boost::headers INTERFACE IMPORTED)
    target_include_directories(Boost::headers INTERFACE "${BOOST_HEADERS_DIR}")

    # Polyfill the variable expected by CMakeLists.txt
    set(Boost_INCLUDE_DIR "${BOOST_HEADERS_DIR}")
  endif ()
endif ()
