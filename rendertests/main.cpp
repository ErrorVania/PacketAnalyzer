
#include <imgui/imgui.h>
#include <imgui/imgui_impl_glfw.h>
#include <imgui/imgui_impl_opengl3.h>
#include <iostream>

#include <GL/gl3w.h>            // Initialize with gl3wInit()

#include <GLFW/glfw3.h>

#include "pcapreader/pcapreader.h"
#include "main_loop.h"

#define VSYNC 1


static void glfw_error_callback(int error, const char* description)
{
    fprintf(stderr, "Glfw Error %d: %s\n", error, description);
}



int main(int, char**)
{
    
    glfwSetErrorCallback(glfw_error_callback);
    if (glfwInit() == GLFW_FALSE) {
        std::cerr << "Failed GLFW Init" << std::endl;
        exit(1);
    }
    std::cout << "GLFW Init success" << std::endl;


    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);


    GLFWwindow* window = glfwCreateWindow(1280, 720, "Dear ImGui GLFW+OpenGL3 example", NULL, NULL);
    if (window == NULL)
        return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(VSYNC); // Enable vsync


    if (gl3wInit() != 0)
    {
        std::cerr << "Failed to initialize OpenGL loader!" << std::endl;
        exit(2);
    }
    std::cout << "GL3W Init success" << std::endl;



    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");


    doStuff(window);

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}