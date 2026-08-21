if (PROJECT_IGNORE_SYSTEM_LIB OR NOT VENDORED_AS_SYSTEM_LIB_FOUND)
    # Note that this could also be handled by: ExternalProject_Add
    # However, FetchContent is a more flexible way to handle this
    # https://cmake.org/cmake/help/latest/module/ExternalProject.html
    # https://cmake.org/cmake/help/latest/module/FetchContent.html
    include(GNUInstallDirs)
    include(FetchContent)

    # Set ULR based upon CMake definitions
    if (NOT VENDORED_UPSTREAM_URL)
        set(VENDORED_UPSTREAM_URL "https://github.com/basicswap/secp256k1/archive")
    endif()

    if (NOT VENDORED_UPSTREAM_REF)
       message(STATUS "VENDORED_UPSTREAM_REF not set, using default value.")
       set(VENDORED_UPSTREAM_REF "98679b41ab5f03bcc87a0849405de7dc34be04c4")
    endif()

    if (NOT VENDORED_UPSTREAM_SHA)
        message(STATUS "VENDORED_UPSTREAM_SHA not set, using default value.")
        set(VENDORED_UPSTREAM_SHA "f4a850fe414f4a1c8f92f44a5c588cb3264b67a68afb1943e9d31d1ebd24d6d3")
    endif()

    if (NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release)
    endif()

    # SECP256K1_DISABLE_SHARED was dropped upstream in favour of BUILD_SHARED_LIBS,
    # which the vendored library only declares as an option when it is top-level.
    if (VENDORED_LIBRARY_STATIC_BUILD)
        set(BUILD_SHARED_LIBS OFF)
        # -fPIC is needed since we will link it from a shared object
        set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    else()
        set(BUILD_SHARED_LIBS ON)
    endif()

    include(UpdateVendoredLibraryOptions)
    UpdateVendoredLibraryOptions("VENDORED_OPTION" "${VENDORED_LIBRARY_OPTION_PREFIX}")


    FetchContent_Declare(
        vendored_library
        URL "${VENDORED_UPSTREAM_URL}/${VENDORED_UPSTREAM_REF}.tar.gz"
        URL_HASH "SHA256=${VENDORED_UPSTREAM_SHA}"
    )
    FetchContent_MakeAvailable(vendored_library)

    if (NOT IS_DIRECTORY ${vendored_library_SOURCE_DIR}/include)
        message(FATAL_ERROR "The system library: ${VENDORED_LIBRARY_PKG_CONFIG} was not found OR")
        message(FATAL_ERROR "The IGNORE_SYSTEM_LIB flag was not set (${PROJECT_IGNORE_SYSTEM_LIB}) OR")
        message(FATAL_ERROR "The vendored library was not installed correctly (<src>/include does not exists). Exiting")
    else()
        set(VENDORED_HEADERS_DIR "${vendored_library_SOURCE_DIR}/include" CACHE PATH "Path to the vendored headers")

        # Avoid spurious warnings when building the vendored library
        unset(VENDORED_UPSTREAM_URL PARENT_SCOPE)
        unset(VENDORED_UPSTREAM_REF PARENT_SCOPE)
        unset(VENDORED_UPSTREAM_SHA PARENT_SCOPE)
    endif()
else()
    include(UnsetVendoredLibraryOptions)
    UnsetVendoredLibraryOptions("VENDORED_OPTION")
    unset(VENDORED_LIBRARY_OPTION_PREFIX)
    unset(VENDORED_LIBRARY_STATIC_BUILD)
    unset(VENDORED_UPSTREAM_URL)
    unset(VENDORED_UPSTREAM_REF)
    unset(VENDORED_UPSTREAM_SHA)
endif()