#define IMGUI_DISABLE_DEMO_WINDOWS


#include <imgui/imgui.h>
#include <imgui/imgui_impl_glfw.h>
#include <imgui/imgui_impl_opengl3.h>
#include <iostream>

#include <GL/gl3w.h>            // Initialize with gl3wInit()

#include <GLFW/glfw3.h>

#include "pcapreader/pcapreader.h"
#include "imgui_oop.h"
#include <vector>
#include <string>




static void glfw_error_callback(int error, const char* description)
{
    fprintf(stderr, "Glfw Error %d: %s\n", error, description);
}




int main(int, char**)
{
    glfwSetErrorCallback(glfw_error_callback);
    setupGLFW(glfw_error_callback, 1);

    GLFWwindow* window = glfwCreateWindow(1280, 720, "Dear ImGui GLFW+OpenGL3 example", NULL, NULL);
    if (window == NULL)
        return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);


    setupGL3W();

    imguiStart(window);


    doStuff(window);

    imguiEnd();
    glfwEnd(window);

    return 0;
}