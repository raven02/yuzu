// Copyright 2018 yuzu Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "common/assert.h"
#include "video_core/engines/maxwell_3d.h"
#include "video_core/renderer_opengl/gl_shader_decompiler.h"
#include "video_core/renderer_opengl/gl_shader_dumper.h"
#include "video_core/renderer_opengl/gl_shader_gen.h"

namespace OpenGL::GLShader {

using Tegra::Engines::Maxwell3D;

static constexpr u32 PROGRAM_OFFSET{10};

ProgramResult GenerateVertexShader(const ShaderSetup& setup) {
    bool faultyA = false;
    bool faultyB = false;
    std::string out = "#version 430 core\n";
    out += "#extension GL_ARB_separate_shader_objects : enable\n\n";
    out += Decompiler::GetCommonDeclarations();

    out += R"(
out gl_PerVertex {
    vec4 gl_Position;
};

layout(std140) uniform vs_config {
    vec4 viewport_flip;
    uvec4 instance_id;
    uvec4 flip_stage;
};
)";

    if (setup.IsDualProgram()) {
        out += "bool exec_vertex_b();\n";
    }

    ProgramResult program =
        Decompiler::DecompileProgram(setup.program.code, PROGRAM_OFFSET,
                                     Maxwell3D::Regs::ShaderStage::Vertex, "vertex", faultyA)
            .get_value_or({});

    out += program.first;

    out += R"(

void main() {
    position = vec4(0.0, 0.0, 0.0, 0.0);
    exec_vertex();
)";

    if (setup.IsDualProgram()) {
        out += "    exec_vertex_b();";
    }

    out += R"(

    // Check if the flip stage is VertexB
    if (flip_stage[0] == 1) {
        // Viewport can be flipped, which is unsupported by glViewport
        position.xy *= viewport_flip.xy;
    }
    gl_Position = position;

    // TODO(bunnei): This is likely a hack, position.w should be interpolated as 1.0
    // For now, this is here to bring order in lieu of proper emulation
    if (flip_stage[0] == 1) {
        position.w = 1.0;
    }
}

)";
    if (setup.IsDualProgram()) {
        ProgramResult program_b =
            Decompiler::DecompileProgram(setup.program.code_b, PROGRAM_OFFSET,
                                         Maxwell3D::Regs::ShaderStage::Vertex, "vertex_b", faultyB)
                .get_value_or({});
        out += program_b.first;
    }

    if (faultyA) {
        ShaderDumper s(setup.program.code, "VS");
        s.dump();
    }
    if (faultyB) {
        ShaderDumper s(setup.program.code_b, "VS");
        s.dump();
    }
    return {out, program.second};
}

ProgramResult GenerateGeometryShader(const ShaderSetup& setup) {
    bool faulty = false;
    std::string out = "#version 430 core\n";
    out += "#extension GL_ARB_separate_shader_objects : enable\n\n";
    out += Decompiler::GetCommonDeclarations();
    out += "bool exec_geometry();\n";

    ProgramResult program =
        Decompiler::DecompileProgram(setup.program.code, PROGRAM_OFFSET,
                                     Maxwell3D::Regs::ShaderStage::Geometry, "geometry", faulty)
            .get_value_or({});
    out += R"(
out gl_PerVertex {
    vec4 gl_Position;
};

layout (std140) uniform gs_config {
    vec4 viewport_flip;
    uvec4 instance_id;
    uvec4 flip_stage;
};

void main() {
    exec_geometry();
}

)";
    out += program.first;
    if (faulty) {
        ShaderDumper s(setup.program.code, "GS");
        s.dump();
    }
    return {out, program.second};
}

ProgramResult GenerateFragmentShader(const ShaderSetup& setup) {
    bool faulty = false;
    std::string out = "#version 430 core\n";
    out += "#extension GL_ARB_separate_shader_objects : enable\n\n";
    out += Decompiler::GetCommonDeclarations();
    out += "bool exec_fragment();\n";

    ProgramResult program =
        Decompiler::DecompileProgram(setup.program.code, PROGRAM_OFFSET,
                                     Maxwell3D::Regs::ShaderStage::Fragment, "fragment", faulty)
            .get_value_or({});
    out += R"(
layout(location = 0) out vec4 FragColor0;
layout(location = 1) out vec4 FragColor1;
layout(location = 2) out vec4 FragColor2;
layout(location = 3) out vec4 FragColor3;
layout(location = 4) out vec4 FragColor4;
layout(location = 5) out vec4 FragColor5;
layout(location = 6) out vec4 FragColor6;
layout(location = 7) out vec4 FragColor7;

layout (std140) uniform fs_config {
    vec4 viewport_flip;
    uvec4 instance_id;
    uvec4 flip_stage;
};

void main() {
    exec_fragment();
}

)";
    out += program.first;
    if (faulty) {
        ShaderDumper s(setup.program.code, "FM");
        s.dump();
    }
    return {out, program.second};
}
} // namespace OpenGL::GLShader
