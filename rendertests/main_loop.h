#pragma once

#include <GL/gl3w.h>
#include <GLFW/glfw3.h>
#include <imgui/imgui.h>
#include <imgui/imgui_impl_glfw.h>
#include <imgui/imgui_impl_opengl3.h>
#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>
//#include "pcapreader/protocols.h"

#define ERROR_STREAM std::cerr
#define glsl_version "#version 130"
#pragma region setups

void imguiStart(GLFWwindow* window) {
	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO(); (void)io;
	ImGui::StyleColorsDark();
	ImGui_ImplGlfw_InitForOpenGL(window, true);
	ImGui_ImplOpenGL3_Init(glsl_version);
}
void imguiEnd() {
	ImGui_ImplOpenGL3_Shutdown();
	ImGui_ImplGlfw_Shutdown();
	ImGui::DestroyContext();
}
#pragma endregion


void doStuff(GLFWwindow* window) {


    std::vector<PDU> pdus;
    PcapReader pcapreader;

    //pcapreader.open("C:\\Users\\Joshua\\Desktop\\test.pcap");
    //pcapreader.beginRead(&pdus);
    const pcap::pcap_global_hdr* global_hdr = nullptr;

    bool showtest = false;
    bool pcap_global_info = true;
    bool pcapLoaded = false;
    bool startWindow = true;

    char buffer[MAX_PATH];
    memset(buffer, 0, MAX_PATH);
    strcpy_s(buffer, "C:\\Users\\Joshua\\Desktop\\test.pcap");

    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
    ImVec2 siztest = ImVec2(400, 400);

    // Main loop
    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();


        ImGui::ShowDemoWindow();


        if (startWindow) {
            
            ImGui::Begin("Open Pcap",0,ImGuiWindowFlags_::ImGuiWindowFlags_AlwaysAutoResize);
            ImGui::InputText("File Path", buffer, MAX_PATH);
            ImGui::SameLine();
            if (ImGui::Button("Open")) {
                pcapreader.open(buffer);
                global_hdr = pcapreader.getGHDR();
                pcapreader.beginRead(&pdus);
                pcapLoaded = true;
            
            }

            if (pcapLoaded) {
                ImGui::Checkbox("Show Global Pcap Info", &pcap_global_info);
                ImGui::Checkbox("Show Pcap Info", &showtest);
            }



            ImGui::End();
        }




        if (pcapLoaded && showtest) {
            ImGui::Begin("Test Window", &showtest);
            ImGui::Text("Hello");
            ImGui::SetWindowSize(siztest);
            if (ImGui::CollapsingHeader("Test")) {
                ImGui::Columns(6, "mycolumn", true);
                ImGui::Separator();
                
                for (int i = 0; i < 6; i++) {
                    for (int x = 0; x < 3; x++) {
                        ImGui::Text("AAA");
                    }
                    ImGui::NextColumn();
                    ImGui::Separator();
                }



                //for (int i = 0; i < pdus.size(); i++) ImGui::Text(std::to_string(pdus[i].pkhdr->incl_len).c_str());


            }
            ImGui::End();
        }


        if (pcapLoaded && pcap_global_info) {
            ImGui::Begin("Global Pcap Header",&pcap_global_info,ImGuiWindowFlags_::ImGuiWindowFlags_AlwaysAutoResize);
            ImGui::SetWindowSize(siztest);

            ImGui::Text("Pcap Version:");
            ImGui::SameLine();
            ImGui::Text("%s.%s", std::to_string(global_hdr->version_major).c_str(), std::to_string(global_hdr->version_minor).c_str());


            {
                std::stringstream stream;
                stream << std::hex << global_hdr->magic;
                std::string result(stream.str());
                for (int x = 0; x < result.size(); x++) result[x] = std::toupper(result[x]);
                ImGui::Text("Magic Number: 0x%s", result.c_str());
            }


            ImGui::Text("Network: %d", global_hdr->network);
            ImGui::Text("Captures: %d", pdus.size());


            ImGui::End();
        }
















        // Rendering
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }
}