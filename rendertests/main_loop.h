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
#include "extractPDUinfo.h"
#include <Windows.h>

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
























inline bool endswith(std::string const& value, std::string const& ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());

}










void doStuff(GLFWwindow* window) {


    std::vector<pcap::pcap_pak_hdr*> pdus;
    PcapReader pcapreader;

    const pcap::pcap_global_hdr* global_hdr = nullptr;

    bool showtest = false;
    bool pcap_global_info = true;
    bool pcapLoaded = false;
    bool openPcapDialouge = true;
    bool showfiledialouge = false;
    bool btnPressAuto = false;

    bool* bools = nullptr;

    char buffer[MAX_PATH];
    memset(buffer, 0, MAX_PATH);
    strcpy_s(buffer, "C:\\Users\\Joshua\\Desktop");

    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

    // Main loop
    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();


        ImGui::ShowDemoWindow();


        if (openPcapDialouge) {
            
            ImGui::Begin("Open Pcap",&openPcapDialouge,ImGuiWindowFlags_::ImGuiWindowFlags_AlwaysAutoResize);
            ImGui::InputText("File Path", buffer, MAX_PATH);
            ImGui::SameLine();
            if (ImGui::Button("Open") || btnPressAuto) {
                struct stat s;
                stat(buffer, &s);
                if (s.st_mode & S_IFDIR) {
                    showfiledialouge = true;
                    pcap_global_info = false;
                    pcapLoaded = false;
                }
                else if (s.st_mode & S_IFREG) {
                    showfiledialouge = false;
                    pcapreader.open(buffer);
                    global_hdr = pcapreader.getGHDR();
                    pcapreader.beginRead(&pdus);
                    pcapLoaded = true;
                }
                btnPressAuto = false;
            }

            if (pcapLoaded) {
                ImGui::Checkbox("Show Global Pcap Info", &pcap_global_info);
                ImGui::Checkbox("Show Pcap Info", &showtest);
            }



            ImGui::End();
        }

        if (showfiledialouge) {
            std::vector<std::string> pcaps;
            WIN32_FIND_DATAA data;
            std::string a(buffer);
            if (a.back() == '\\') a += "*"; else a += "\\*";

            
            HANDLE h = FindFirstFileA(a.c_str(), &data);
            if (h != INVALID_HANDLE_VALUE) {
                do {
                    if (endswith(data.cFileName, ".pcap")) {
                        pcaps.push_back(data.cFileName);
                    }
                } while (FindNextFileA(h, &data) != 0);
                FindClose(h);
            }

            ImGui::Begin(buffer, &showfiledialouge, ImGuiWindowFlags_::ImGuiWindowFlags_AlwaysVerticalScrollbar);
            ImGui::SetWindowSize(ImVec2(400, 200));
            if (bools == nullptr) bools = (bool*)malloc(pcaps.size()); else bools = (bool*)realloc(bools, pcaps.size());
            memset(bools, 0, pcaps.size());




            for (int i = 0; i < pcaps.size(); i++) {
                ImGui::Selectable(pcaps[i].c_str(), bools + i);
                if (*(bools + i)) {
                    std::string b(buffer);
                    if (b.back() == '\\') b += pcaps[i]; else b = b + '\\' + pcaps[i];
                    strcpy_s(buffer, b.c_str());
                    showfiledialouge = false;
                    btnPressAuto = true;
                }
            }
            ImGui::End();
        }










        if (pcapLoaded && pcap_global_info) {
            ImGui::Begin("Global Pcap Header",&pcap_global_info,ImGuiWindowFlags_::ImGuiWindowFlags_AlwaysAutoResize);
            ImGui::Text("Pcap Version: %s.%s", std::to_string(global_hdr->version_major).c_str(), std::to_string(global_hdr->version_minor).c_str());

            
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



        if (pcapLoaded && showtest) {
            ImGui::Begin("Test", &showtest);

            ImGui::SetWindowSize(ImVec2(700, 400));
            
            if (ImGui::BeginTable("TestTable", 4,ImGuiTableFlags_::ImGuiTableFlags_Borders | ImGuiTableFlags_::ImGuiTableFlags_Resizable)) {
                ImGui::TableSetupColumn("Nr. ");
                ImGui::TableSetupColumn("Source");
                ImGui::TableSetupColumn("Destination");
                ImGui::TableSetupColumn("Length");
                ImGui::TableHeadersRow();
                for (int i = 0; i < pdus.size(); i++) {
                    ImGui::TableNextColumn();
                    ImGui::Text("%d", i);
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", getSource(pdus[i]).c_str());
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", getDest(pdus[i]).c_str()); 
                    ImGui::TableNextColumn();
                    ImGui::Text("%d", pdus[i]->incl_len);
                    ImGui::TableNextRow();
                }
                ImGui::EndTable();
            }



            

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
    free(bools);
}