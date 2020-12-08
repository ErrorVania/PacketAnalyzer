#pragma once

#include <imgui/imgui.h>
#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>
#include <Windows.h>
#include "extractPDUinfo.h"
#include <imgui/imfilebrowser.h>

inline bool endswith(std::string const& value, std::string const& ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

void doStuff(GLFWwindow* window) {
    ImGui::FileBrowser fb;
    fb.SetTitle("Select a PCAP");
    fb.SetTypeFilters({ ".pcap" });

    std::vector<pcap_pak_hdr*> pdus;
    PcapReader pcapreader;

    const pcap_global_hdr* global_hdr = nullptr;

    bool showtest = false;
    bool pcap_global_info = true;
    bool pcapLoaded = false;
    bool openPcapDialouge = true;
    bool showfiledialouge = false;
    bool btnPressAuto = false;

    bool* bools = nullptr;

    char buffer[MAX_PATH];
    memset(buffer, 0, MAX_PATH);
    //strcpy_s(buffer, "");

    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

    // Main loop
    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();


        ImGui::ShowDemoWindow();

        ImGui::PushItemWidth(300);
        if (openPcapDialouge) {
           
            ImGui::Begin("Open Pcap",&openPcapDialouge,ImGuiWindowFlags_::ImGuiWindowFlags_AlwaysAutoResize);
            ImGui::Text("%.3f ms/frame (%.1f FPS)", 1000.0f / ImGui::GetIO().Framerate, ImGui::GetIO().Framerate);
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
            ImGui::SameLine();
            if (ImGui::Button("...")) {
                fb.Open();
            }

            fb.Display();
            if (fb.HasSelected()) {
                strcpy_s(buffer, fb.GetSelected().string().c_str());
                btnPressAuto = true;
            }



            if (pcapLoaded) {
                ImGui::Checkbox("Show Global Pcap Info", &pcap_global_info);
                ImGui::Checkbox("Show Pcap Info", &showtest);
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
                for (unsigned x = 0; x < result.size(); x++) result[x] = std::toupper(result[x]);
                ImGui::Text("Magic Number: 0x%s", result.c_str());
            }

            ImGui::Text("Network: %d", global_hdr->network);
            ImGui::Text("Captures: %d", pdus.size());


            ImGui::End();
        }



        if (pcapLoaded && showtest) {
            ImGui::Begin("Test", &showtest);

            ImGui::SetWindowSize(ImVec2(700, 400));
            
            if (ImGui::BeginTable("TestTable", 5,ImGuiTableFlags_::ImGuiTableFlags_Borders | ImGuiTableFlags_::ImGuiTableFlags_Resizable)) {
                ImGui::TableSetupColumn("Nr. ");
                ImGui::TableSetupColumn("Source");
                ImGui::TableSetupColumn("Destination");
		        ImGui::TableSetupColumn("Protocol");
                ImGui::TableSetupColumn("Length");
                
                
                
                
                ImGui::TableHeadersRow();
                for (unsigned i = 0; i < pdus.size(); i++) {
                    ImGui::TableNextColumn();
                    ImGui::Text("%d", i);
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", getSource(pdus[i]).c_str());
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", getDest(pdus[i]).c_str()); 
		            ImGui::TableNextColumn();
		            ImGui::Text("%s",lastProtoL2(pdus[i]).c_str());
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
