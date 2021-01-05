#pragma once

#include <imgui/imgui.h>
#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>
#include <Windows.h>
#include "extractPDUinfo.h"
#include <imgui/imfilebrowser.h>


/*void doStuff(GLFWwindow* window) {
    

    std::vector<pcap_pak_hdr*> pdus;
    PcapReader pcapreader;

    const pcap_global_hdr* global_hdr = nullptr;

    bool showtest = false;
    bool pcapLoaded = false;
    bool openPcapDialouge = true;
    bool btnPressAuto = false;
    char buffer[MAX_PATH];
    ImVec2 fileselectorwindow = ImVec2(0,0);

    const ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
    ImGui::FileBrowser fb;
    const std::vector<const char*> columns = {"Nr.","Time","Source","Destination","Protocol","Length"};


    memset(buffer, 0, MAX_PATH);
    fb.SetTitle("Select a PCAP");
    fb.SetTypeFilters({ ".pcap" });

    // Main loop
    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();


        ImGui::ShowDemoWindow();

        if (openPcapDialouge) {
            ImGui::SetNextWindowPos(ImVec2(0, 0));

            ImGui::Begin("Open Pcap",0,ImGuiWindowFlags_::ImGuiWindowFlags_AlwaysAutoResize);
            ImGui::Text("%.3f ms/frame (%.1f FPS)", 1000.0f / ImGui::GetIO().Framerate, ImGui::GetIO().Framerate);
            ImGui::InputText("Select File", buffer, MAX_PATH);
            ImGui::SameLine();
            if (ImGui::Button("Open") || btnPressAuto) {
                struct stat s;
                stat(buffer, &s);
                if (s.st_mode & S_IFREG) {
                    pcapreader.open(buffer);
                    global_hdr = pcapreader.getGHDR();
                    if (global_hdr != nullptr && global_hdr->magic == 0xA1B2C3D4) {
                        pcapreader.beginRead(&pdus);
                        pcapLoaded = true;
                    }
                    else {
                        pcapLoaded = false;
                        MessageBoxA(NULL, "Invalid file Format or wrong endianness!","PCAP Error",MB_OK);
                    }
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
            }

            if (pcapLoaded && global_hdr) {
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
                ImGui::Checkbox("Show Pcap Info", &showtest);
            }
            fileselectorwindow = ImGui::GetWindowSize();
            ImGui::End();
        }



        if (pcapLoaded && showtest) {
            ImGui::SetNextWindowPos(ImVec2(fileselectorwindow.x, 0));
            ImGui::Begin("Test", &showtest, ImGuiWindowFlags_::ImGuiWindowFlags_AlwaysAutoResize);
            //ImGui::SetWindowSize(ImVec2(700, 400));
            
            if (ImGui::BeginTable("Data", columns.size(),ImGuiTableFlags_::ImGuiTableFlags_Borders | ImGuiTableFlags_::ImGuiTableFlags_Resizable)) {
                for (const char* _a : columns) {
                    ImGui::TableSetupColumn(_a);
                }
                
                
                ImGui::TableHeadersRow();
                for (unsigned i = 0; i < pdus.size(); i++) {
                    ImGui::TableNextColumn();
                    ImGui::Text("%d", i);
                    ImGui::TableNextColumn();
                    ImGui::Text("%.3fs", pdus[i]->ts_usec / 1000000.0f);
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
}*/



class ImGuiDrawer {
public:

    std::vector<pcap_pak_hdr*> pdus;
    PcapReader pcapreader;

    const pcap_global_hdr* global_hdr;
    bool showtest, pcapLoaded, openPcapDialouge, btnPressAuto;
    char buffer[MAX_PATH];
    ImVec2 fileselectorwindowsize;
    ImVec4 clear_color;
    ImGui::FileBrowser fb;
    std::vector<const char*> columns;
    const int* w;
    const int* h;

    ImGuiDrawer(const int* width, const int* height) {
        w = width;
        h = height;
        global_hdr = nullptr;

        showtest = false;
        pcapLoaded = false;
        openPcapDialouge = true;
        btnPressAuto = false;
        fileselectorwindowsize = ImVec2(0, 0);

        clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
        columns = { "Nr.","Time","Source","Destination","Protocol","Length" };


        memset(buffer, 0, MAX_PATH);
        fb.SetTitle("Select a PCAP");
        fb.SetTypeFilters({ ".pcap" });
    }


    void doLoop(GLFWwindow* window) {
        while (!glfwWindowShouldClose(window))
        {
            glfwPollEvents();

            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplGlfw_NewFrame();
            ImGui::NewFrame();


            ImGui::ShowDemoWindow();

            if (openPcapDialouge) {
                ImGui::SetNextWindowPos(ImVec2(0, 0));

                ImGui::Begin("Open Pcap", 0, ImGuiWindowFlags_::ImGuiWindowFlags_AlwaysAutoResize);
                ImGui::Text("%.3f ms/frame (%.1f FPS)", 1000.0f / ImGui::GetIO().Framerate, ImGui::GetIO().Framerate);
                ImGui::InputText("Select File", buffer, MAX_PATH);
                ImGui::SameLine();
                if (ImGui::Button("Open") || btnPressAuto) {
                    struct stat s;
                    stat(buffer, &s);
                    if (s.st_mode & S_IFREG) {
                        pcapreader.open(buffer);
                        global_hdr = pcapreader.getGHDR();
                        if (global_hdr != nullptr && global_hdr->magic == 0xA1B2C3D4) {
                            pcapreader.beginRead(&pdus);
                            pcapLoaded = true;
                        }
                        else {
                            pcapLoaded = false;
                            MessageBoxA(NULL, "Invalid file Format or wrong endianness!", "PCAP Error", MB_OK);
                        }
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
                }

                if (pcapLoaded && global_hdr) {
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
                    ImGui::Checkbox("Show Pcap Info", &showtest);
                }
                fileselectorwindowsize = ImGui::GetWindowSize();
                ImGui::End();
            }

            static Resolver res;

            if (pcapLoaded && showtest) {
                ImGui::SetNextWindowPos(ImVec2(fileselectorwindowsize.x, 0));
                ImGui::SetNextWindowSize(ImVec2(*w - fileselectorwindowsize.x, *h));
                ImGui::Begin("Test", &showtest);


                if (ImGui::BeginTable("Data", columns.size(), ImGuiTableFlags_::ImGuiTableFlags_Borders | ImGuiTableFlags_::ImGuiTableFlags_Resizable)) {
                    for (const char* _a : columns) {
                        ImGui::TableSetupColumn(_a);
                    }


                    ImGui::TableHeadersRow();
                    for (unsigned i = 0; i < pdus.size(); i++) {
                        ImGui::TableNextColumn();
                        ImGui::Text("%d", i);
                        ImGui::TableNextColumn();
                        ImGui::Text("%.3fs", pdus[i]->ts_usec / 1000000.0f);
                        ImGui::TableNextColumn();
                        ImGui::Text("%s", getSource(pdus[i]).c_str());
                        ImGui::TableNextColumn();
                        ImGui::Text("%s", getDest(pdus[i]).c_str());
                        ImGui::TableNextColumn();
                        ImGui::Text("%s", lastProtoL2(pdus[i]).c_str());
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
    }



};