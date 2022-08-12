#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "bypasscore/bypasscore.h"
#include "bypasscore/memory/scanner.h"
#include "bypasscore/memory/region.h"
#include "bypasscore/binary/pe.h"
#include "bypasscore/process/process.h"
#include "bypasscore/platform/os.h"
#include "bypasscore/platform/arch.h"
#include "bypasscore/util/hash.h"

namespace py = pybind11;

PYBIND11_MODULE(pybypasscore, m) {
    m.doc() = "BypassCore SDK Python bindings";

    // SDK init/shutdown
    m.def("initialize", &bypasscore::initialize, "Initialize the SDK");
    m.def("shutdown", &bypasscore::shutdown, "Shut down the SDK");

    // Platform info
    m.def("get_os_version", []() {
        auto v = bypasscore::platform::get_os_version();
        return py::dict(
            "major"_a = v.major, "minor"_a = v.minor,
            "build"_a = v.build, "name"_a = v.name);
    });
    m.def("is_elevated", &bypasscore::platform::is_elevated);
    m.def("target_arch", []() {
        return bypasscore::platform::arch_name(bypasscore::platform::target_arch());
    });

    // Hashing
    m.def("fnv1a_32", [](const std::string& s) {
        return bypasscore::hash32(s.c_str(), s.size());
    }, "FNV-1a 32-bit hash");
    m.def("fnv1a_64", [](const std::string& s) {
        return bypasscore::hash64(s.c_str());
    }, "FNV-1a 64-bit hash");

    // Pattern scanning
    m.def("parse_pattern", [](const std::string& pattern) {
        auto result = bypasscore::memory::parse_pattern(pattern);
        if (!result) throw std::runtime_error(result.error().message);
        std::vector<py::dict> entries;
        for (const auto& pb : *result) {
            entries.push_back(py::dict(
                "value"_a = pb.value,
                "wildcard"_a = pb.wildcard));
        }
        return entries;
    }, "Parse an AOB pattern string");

    m.def("scan_buffer", [](py::bytes data, const std::string& pattern) {
        auto parsed = bypasscore::memory::parse_pattern(pattern);
        if (!parsed) throw std::runtime_error(parsed.error().message);
        std::string buf = data;
        auto offset = bypasscore::memory::scan_buffer(
            reinterpret_cast<const uint8_t*>(buf.data()), buf.size(), *parsed);
        if (offset) return static_cast<int64_t>(*offset);
        return static_cast<int64_t>(-1);
    }, "Scan a buffer for a pattern");

    // PE parsing
    py::class_<bypasscore::binary::Section>(m, "Section")
        .def_readonly("name", &bypasscore::binary::Section::name)
        .def_readonly("virtual_address", &bypasscore::binary::Section::virtual_address)
        .def_readonly("virtual_size", &bypasscore::binary::Section::virtual_size)
        .def_readonly("raw_offset", &bypasscore::binary::Section::raw_offset)
        .def_readonly("raw_size", &bypasscore::binary::Section::raw_size)
        .def("is_executable", &bypasscore::binary::Section::is_executable)
        .def("is_readable", &bypasscore::binary::Section::is_readable)
        .def("is_writable", &bypasscore::binary::Section::is_writable);

    // Process enumeration
    m.def("enumerate_processes", []() {
        auto procs = bypasscore::process::Process::enumerate();
        std::vector<py::dict> result;
        for (const auto& p : procs) {
            result.push_back(py::dict(
                "pid"_a = p.pid, "name"_a = p.name,
                "parent_pid"_a = p.parent_pid));
        }
        return result;
    }, "Enumerate running processes");
}
