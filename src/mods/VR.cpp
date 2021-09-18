#include <fstream>

#if defined(RE2) || defined(RE3)
#include "sdk/regenny/re3/via/Window.hpp"
#include "sdk/regenny/re3/via/SceneView.hpp"
#else 
#include "sdk/regenny/re8/via/Window.hpp"
#include "sdk/regenny/re8/via/SceneView.hpp"
#endif

#include "sdk/Math.hpp"
#include "sdk/SceneManager.hpp"
#include "sdk/RETypeDB.hpp"

#include "utility/Scan.hpp"
#include "utility/FunctionHook.hpp"
#include "utility/Module.hpp"

#include "VR.hpp"

constexpr auto CONTROLLER_DEADZONE = 0.1f;
#ifdef RE8
constexpr auto OVERLAY_DRAW_INDEX = 14;
#else
constexpr auto OVERLAY_DRAW_INDEX = 12;
#endif

std::shared_ptr<VR>& VR::get() {
    static std::shared_ptr<VR> inst{};

    if (inst == nullptr) {
        inst = std::make_shared<VR>();
    }

    return inst;
}

std::unique_ptr<FunctionHook> g_get_size_hook{};
std::unique_ptr<FunctionHook> g_input_hook{};
std::unique_ptr<FunctionHook> g_projection_matrix_hook{};
std::unique_ptr<FunctionHook> g_view_matrix_hook{};

// Purpose: spoof the render target size to the size of the HMD displays
float* VR::get_size_hook(REManagedObject* scene_view, float* result) {
    auto original_func = g_get_size_hook->get_original<decltype(VR::get_size_hook)>();
    auto mod = VR::get();

    auto out = original_func(scene_view, result);

//#if defined(RE2) || defined(RE3)
    auto regenny_view = (regenny::via::SceneView*)scene_view;
    auto window = regenny_view->window;

    // Force the display to stretch to the window size
    regenny_view->display_type = regenny::via::DisplayType::Fit;

    // Set the window size, which will increase the size of the backbuffer
    if (window != nullptr) {
        window->width = mod->get_hmd_width();
        window->height = mod->get_hmd_height();
    }
//#endif

    // spoof the size to the HMD's size
    out[0] = (float)mod->get_hmd_width();
    out[1] = (float)mod->get_hmd_height();

    return out;
}

Matrix4x4f* VR::camera_get_projection_matrix_hook(REManagedObject* camera, Matrix4x4f* result) {
    auto original_func = g_projection_matrix_hook->get_original<decltype(VR::camera_get_projection_matrix_hook)>();

    auto vr = VR::get();

    if (result == nullptr || !vr->m_use_afr) {
        return original_func(camera, result);
    }

    if (camera != sdk::get_primary_camera()) {
        return original_func(camera, result);
    }

#ifdef RE8
    static auto once = false;

    if (!once) {        
        vr->m_nearz = sdk::call_object_func<float>(camera, "get_NearClipPlane", sdk::get_thread_context(), camera);
        vr->m_farz = sdk::call_object_func<float>(camera, "get_FarClipPlane", sdk::get_thread_context(), camera);

        once = true;
    }
#endif

    // Get the projection matrix for the correct eye
    // For some reason we need to flip the projection matrix here?
    *result = vr->get_current_projection_matrix(!(vr->m_frame_count < vr->get_frame_count()));

    return result;
}

Matrix4x4f* VR::camera_get_view_matrix_hook(REManagedObject* camera, Matrix4x4f* result) {
    auto original_func = g_view_matrix_hook->get_original<decltype(VR::camera_get_view_matrix_hook)>();

    auto vr = VR::get();

    if (result == nullptr || !vr->m_use_afr) {
        return original_func(camera, result);
    }

    /*if (camera != sdk::get_primary_camera()) {
        return original_func(camera, result);
    }*/

    original_func(camera, result);

    auto& mtx = *result;

    const auto current_eye_transform = vr->get_current_eye_transform();

    /*if (vr->m_use_rotation) {
        if (vr->m_invert) {
            mtx *= glm::inverse(glm::extractMatrixRotation(current_eye_transform));
        } else {
            mtx *= glm::extractMatrixRotation(current_eye_transform);
        }
    }*/

    // Adjust the view matrix origin
    *(Vector3f*)&mtx[3] += Vector3f { current_eye_transform[3] };

    return result;
}

void VR::inputsystem_update_hook(void* ctx, REManagedObject* input_system) {
    auto original_func = g_input_hook->get_original<decltype(VR::inputsystem_update_hook)>();

    auto mod = VR::get();
    const auto now = std::chrono::steady_clock::now();
    auto is_using_controller = (now - mod->get_last_controller_update()) <= std::chrono::seconds(10);

    if (mod->get_controllers().empty()) {
        // no controllers connected, don't do anything
        original_func(ctx, input_system);
        return;
    }

    auto lstick = sdk::call_object_func<REManagedObject*>(input_system, "get_LStick", sdk::get_thread_context());
    auto rstick = sdk::call_object_func<REManagedObject*>(input_system, "get_RStick", sdk::get_thread_context());

    if (lstick == nullptr || rstick == nullptr) {
        original_func(ctx, input_system);
        return;
    }

    auto button_bits_obj = sdk::call_object_func<REManagedObject*>(input_system, "get_ButtonBits", sdk::get_thread_context(), input_system);

    if (button_bits_obj == nullptr) {
        original_func(ctx, input_system);
        return;
    }

    auto left_axis = mod->get_left_stick_axis();
    auto right_axis = mod->get_right_stick_axis();
    const auto left_axis_len = glm::length(left_axis);
    const auto right_axis_len = glm::length(right_axis);

    // Current actual button bits used by the game
    auto& button_bits_down = *sdk::get_object_field<uint64_t>(button_bits_obj, "Down");
    auto& button_bits_on = *sdk::get_object_field<uint64_t>(button_bits_obj, "On");
    auto& button_bits_up = *sdk::get_object_field<uint64_t>(button_bits_obj, "Up");

    //button_bits_down |= mod->m_button_states_down.to_ullong();
    //button_bits_on |= mod-> m_button_states_on.to_ullong();
    //button_bits_up |= mod->m_button_states_up.to_ullong();

    auto keep_button_down = [&](app::ropeway::InputDefine::Kind button) {
        if ((mod->m_button_states_on.to_ullong() & (uint64_t)button) == 0 && (mod->m_button_states_down.to_ullong() & (uint64_t)button) == 0) {
            return;
        }

        if ((mod->m_button_states_on.to_ullong() & (uint64_t)button) == 0) {
            if (mod->m_button_states_down.to_ullong() & (uint64_t)button) {
                button_bits_on |= (uint64_t)button;
                button_bits_down &= ~(uint64_t)button;
            } else {
                button_bits_down |= (uint64_t)button;
            }
        } else {
            button_bits_down &= ~(uint64_t)button;
            button_bits_on |= (uint64_t)button;
        }
    };

    if (left_axis_len > CONTROLLER_DEADZONE) {
        mod->m_last_controller_update = now;
        is_using_controller = true;

        // Override the left stick's axis values to the VR controller's values
        Vector3f axis{ left_axis.x, left_axis.y, 0.0f };
        sdk::call_object_func<void*>(lstick, "update", sdk::get_thread_context(), lstick, &axis, &axis);

        keep_button_down(app::ropeway::InputDefine::Kind::UI_L_STICK);
    }

    if (right_axis_len > CONTROLLER_DEADZONE) {
        mod->m_last_controller_update = now;
        is_using_controller = true;

        // Override the right stick's axis values to the VR controller's values
        Vector3f axis{ right_axis.x, right_axis.y, 0.0f };
        sdk::call_object_func<void*>(rstick, "update", sdk::get_thread_context(), rstick, &axis, &axis);

        keep_button_down(app::ropeway::InputDefine::Kind::UI_R_STICK);
    }

    // Causes the right stick to take effect properly
    if (is_using_controller) {
        sdk::call_object_func<void*>(input_system, "set_InputMode", sdk::get_thread_context(), input_system, app::ropeway::InputDefine::InputMode::Pad);
    }

    original_func(ctx, input_system);

    mod->openvr_input_to_game(input_system);
}

// Called when the mod is initialized
std::optional<std::string> VR::on_initialize() {
    auto openvr_error = initialize_openvr();

    if (openvr_error) {
        return openvr_error;
    }

    auto hijack_error = hijack_resolution();

    if (hijack_error) {
        return hijack_error;
    }

    hijack_error = hijack_input();

    if (hijack_error) {
        return hijack_error;
    }

    hijack_error = hijack_camera();

    if (hijack_error) {
        return hijack_error;
    }

    hijack_error = hijack_overlay_renderer();

    if (hijack_error) {
        return hijack_error;
    }

    // all OK
    return Mod::on_initialize();
}

std::optional<std::string> VR::initialize_openvr() {
    auto error = vr::VRInitError_None;
	m_hmd = vr::VR_Init(&error, vr::VRApplication_Scene);

    // check if error
    if (error != vr::VRInitError_None) {
        return "VR_Init failed: " + std::string{vr::VR_GetVRInitErrorAsEnglishDescription(error)};
    }

    if (m_hmd == nullptr) {
        return "VR_Init failed: HMD is null";
    }

    // get render target size
    m_hmd->GetRecommendedRenderTargetSize(&m_w, &m_h);

    if (!vr::VRCompositor()) {
        return "VRCompositor failed to initialize.";
    }

    const auto module_directory = *utility::get_module_directory(g_framework->get_module().as<HMODULE>());

    // write default actions and bindings with the static strings we have
    for (auto& it : m_binding_files) {
        spdlog::info("Writing default binding file {}", it.first);

        std::ofstream file{ module_directory + "/" + it.first };
        file << it.second;
    }

    const auto actions_path = module_directory + "/actions.json";
    auto input_error = vr::VRInput()->SetActionManifestPath(actions_path.c_str());

    if (input_error != vr::VRInputError_None) {
        return "VRInput failed to set action manifest path: " + std::to_string((uint32_t)input_error);
    }

    // get action set
    auto action_set_error = vr::VRInput()->GetActionSetHandle("/actions/default", &m_action_set);

    if (action_set_error != vr::VRInputError_None) {
        return "VRInput failed to get action set: " + std::to_string((uint32_t)action_set_error);
    }

    if (m_action_set == vr::k_ulInvalidActionSetHandle) {
        return "VRInput failed to get action set handle.";
    }

    // get action handles
    auto trigger_error = vr::VRInput()->GetActionHandle("/actions/default/in/Trigger", &m_action_trigger);
    auto grip_error = vr::VRInput()->GetActionHandle("/actions/default/in/Grip", &m_action_grip);

    if (trigger_error != vr::VRInputError_None || grip_error != vr::VRInputError_None) {
        return "VRInput failed to get action handles: " + std::to_string((uint32_t)trigger_error) + " " + std::to_string((uint32_t)grip_error);
    }

    if (m_action_trigger == vr::k_ulInvalidActionHandle || m_action_grip == vr::k_ulInvalidActionHandle) {
        return "VRInput failed to get action handles.";
    }

    auto joystick_error = vr::VRInput()->GetActionHandle("/actions/default/in/Joystick", &m_action_joystick);

    if (joystick_error != vr::VRInputError_None) {
        return "VRInput failed to get action handles (Joystick): " + std::to_string((uint32_t)joystick_error);
    }

    auto joystick_click_error = vr::VRInput()->GetActionHandle("/actions/default/in/JoystickClick", &m_action_joystick_click);

    if (joystick_click_error != vr::VRInputError_None) {
        return "VRInput failed to get action handles (JoystickClick): " + std::to_string((uint32_t)joystick_click_error);
    }

    auto a_button_error = vr::VRInput()->GetActionHandle("/actions/default/in/AButton", &m_action_a_button);

    if (a_button_error != vr::VRInputError_None) {
        return "VRInput failed to get action handles (AButton): " + std::to_string((uint32_t)a_button_error);
    }

    auto b_button_error = vr::VRInput()->GetActionHandle("/actions/default/in/BButton", &m_action_b_button);

    if (b_button_error != vr::VRInputError_None) {
        return "VRInput failed to get action handles (BButton): " + std::to_string((uint32_t)b_button_error);
    }

    m_active_action_set.ulActionSet = m_action_set;
    m_active_action_set.ulRestrictedToDevice = vr::k_ulInvalidInputValueHandle;
    m_active_action_set.nPriority = 0;

    auto left_joystick_origin_error = vr::EVRInputError::VRInputError_None;
    auto right_joystick_origin_error = vr::EVRInputError::VRInputError_None;

    vr::InputOriginInfo_t left_joystick_origin_info{};
    vr::InputOriginInfo_t right_joystick_origin_info{};

    const auto start_time = std::chrono::steady_clock::now();
    auto iterations = 0;

    // Get input origin info for the joysticks
    do {
        ++iterations;
        
        const auto now = std::chrono::steady_clock::now();

        if (now - start_time >= std::chrono::seconds(5)) {
            break;
        }

        // get the source input device handles for the joysticks
        auto left_joystick_error = vr::VRInput()->GetInputSourceHandle("/user/hand/left", &m_left_joystick);

        if (left_joystick_error != vr::VRInputError_None) {
            continue;
        }

        auto right_joystick_error = vr::VRInput()->GetInputSourceHandle("/user/hand/right", &m_right_joystick);

        if (right_joystick_error != vr::VRInputError_None) {
            continue;
        }

        left_joystick_origin_info = {};
        right_joystick_origin_info = {};

        left_joystick_origin_error = vr::VRInput()->GetOriginTrackedDeviceInfo(m_left_joystick, &left_joystick_origin_info, sizeof(left_joystick_origin_info));
        right_joystick_origin_error = vr::VRInput()->GetOriginTrackedDeviceInfo(m_right_joystick, &right_joystick_origin_info, sizeof(right_joystick_origin_info));
    } while (left_joystick_origin_error != vr::EVRInputError::VRInputError_None 
            || right_joystick_origin_error != vr::EVRInputError::VRInputError_None);

    spdlog::info("VRInput: GetOriginTrackedDeviceInfo took {} iterations", iterations);

    if (left_joystick_origin_error != vr::VRInputError_None || right_joystick_origin_error != vr::VRInputError_None) {
        return "VRInput failed to get controller device info (left, right): " + std::to_string((uint32_t)left_joystick_origin_error) + ", " + std::to_string((uint32_t)right_joystick_origin_error);
    }

    // Instead of manually going through the devices,
    // We do this. The order of the devices isn't always guaranteed to be
    // Left, and then right. Using the input state handles will always
    // Get us the correct device indices.
    m_controllers.push_back(left_joystick_origin_info.trackedDeviceIndex);
    m_controllers.push_back(right_joystick_origin_info.trackedDeviceIndex);
    m_controllers_set.insert(left_joystick_origin_info.trackedDeviceIndex);
    m_controllers_set.insert(right_joystick_origin_info.trackedDeviceIndex);

    spdlog::info("Left Hand: {}", left_joystick_origin_info.trackedDeviceIndex);
    spdlog::info("Right Hand: {}", right_joystick_origin_info.trackedDeviceIndex);
    return std::nullopt;
}

std::optional<std::string> VR::hijack_resolution() {
    // We're going to hook via.SceneView.get_Size so we can
    // spoof the render target size to the HMD's resolution.
    auto get_size_func = sdk::find_native_method("via.SceneView", "get_Size");

    if (get_size_func == nullptr) {
        return "VR init failed: via.SceneView.get_Size function not found.";
    }

    spdlog::info("via.SceneView.get_Size: {:x}", (uintptr_t)get_size_func);

    // Pattern scan for the native function call
    auto ref = utility::scan((uintptr_t)get_size_func, 0x100, "49 8B C8 E8");

    if (!ref) {
        return "VR init failed: via.SceneView.get_Size native function not found. Pattern scan failed.";
    }

    auto native_func = utility::calculate_absolute(*ref + 4);

    // Hook the native function
    g_get_size_hook = std::make_unique<FunctionHook>(native_func, get_size_hook);

    if (!g_get_size_hook->create()) {
        return "VR init failed: via.SceneView.get_Size native function hook failed.";
    }

    return std::nullopt;
}

std::optional<std::string> VR::hijack_input() {
#ifndef RE8
    // We're going to hook InputSystem.update so we can
    // override the analog stick values with the VR controller's
    auto func = sdk::find_native_method(game_namespace("InputSystem"), "update");

    if (func == nullptr) {
        return "VR init failed: InputSystem.update function not found.";
    }

    spdlog::info("InputSystem.update: {:x}", (uintptr_t)func);

    // Hook the native function
    g_input_hook = std::make_unique<FunctionHook>(func, inputsystem_update_hook);

    if (!g_input_hook->create()) {
        return "VR init failed: InputSystem.update native function hook failed.";
    }
#endif

    return std::nullopt;
}

std::optional<std::string> VR::hijack_camera() {
    // We're going to hook via.Camera.get_ProjectionMatrix so we can
    // override the camera's Projection matrix with the HMD's Projection matrix (per-eye)
    auto func = sdk::find_native_method("via.Camera", "get_ProjectionMatrix");

    if (func == nullptr) {
        return "VR init failed: via.Camera.get_ProjectionMatrix function not found.";
    }

    spdlog::info("via.Camera.get_ProjectionMatrix: {:x}", (uintptr_t)func);
    
    // Pattern scan for the native function call
    auto ref = utility::scan((uintptr_t)func, 0x100, "49 8B C8 E8");

    if (!ref) {
        return "VR init failed: via.Camera.get_ProjectionMatrix native function not found. Pattern scan failed.";
    }

    auto native_func = utility::calculate_absolute(*ref + 4);

    // Hook the native function
    g_projection_matrix_hook = std::make_unique<FunctionHook>(native_func, camera_get_projection_matrix_hook);

    if (!g_projection_matrix_hook->create()) {
        return "VR init failed: via.Camera.get_ProjectionMatrix native function hook failed.";
    }

    ///////////////////////////////
    // Hook view matrix start
    ///////////////////////////////
    func = sdk::find_native_method("via.Camera", "get_ViewMatrix");

    if (func == nullptr) {
        return "VR init failed: via.Camera.get_ViewMatrix function not found.";
    }

    spdlog::info("via.Camera.get_ViewMatrix: {:x}", (uintptr_t)func);

    // Pattern scan for the native function call
    ref = utility::scan((uintptr_t)func, 0x100, "49 8B C8 E8");

    if (!ref) {
        return "VR init failed: via.Camera.get_ViewMatrix native function not found. Pattern scan failed.";
    }

    native_func = utility::calculate_absolute(*ref + 4);

    // Hook the native function
    g_view_matrix_hook = std::make_unique<FunctionHook>(native_func, camera_get_view_matrix_hook);

    if (!g_view_matrix_hook->create()) {
        return "VR init failed: via.Camera.get_ViewMatrix native function hook failed.";
    }

    return std::nullopt;
}

std::optional<std::string> VR::hijack_overlay_renderer() {
    // We're going to make via.render.layer.Overlay.Draw() return early
    // For some reason this fixes 3D GUI rendering in RE3 in VR
    auto t = sdk::RETypeDB::get()->find_type("via.render.layer.Overlay");

    if (t == nullptr) {
        return "VR init failed: via.render.layer.Overlay type not found.";
    }

    auto managed_type = t->type;

    if (managed_type == nullptr) {
        return "VR init failed: via.render.layer.Overlay managed type not found.";
    }

    auto type_vtable = *(uintptr_t**)managed_type;

    if (type_vtable == nullptr) {
        return "VR init failed: via.render.layer.Overlay vtable not found.";
    }

    // We're going to construct a fake instance of the object
    // So we can get the address of the Draw() method which is
    // a virtual function
    void** (*create_instance)(void* obj, void** result, void* buffer) = decltype(create_instance)(type_vtable[1]);

    if (create_instance == nullptr) {
        return "VR init failed: via.render.layer.Overlay type create_instance function not found.";
    }

    auto test = (uintptr_t)create_instance - g_framework->get_module().as<uintptr_t>();
    spdlog::info("via.render.layer.Overlay.create_instance: {:x}", test);

    void* fake_obj = nullptr;
    create_instance(nullptr, &fake_obj, nullptr);

    if (fake_obj == nullptr) {
        return "VR init failed: Failed to create fake via.render.layer.Overlay instance.";
    }

    auto obj_vtable = *(uintptr_t**)fake_obj;

    if (obj_vtable == nullptr) {
        return "VR init failed: via.render.layer.Overlay vtable not found.";
    }

    auto draw_native = obj_vtable[OVERLAY_DRAW_INDEX];

    if (draw_native == 0) {
        return "VR init failed: via.render.layer.Overlay draw native not found.";
    }

    spdlog::info("via.render.layer.Overlay.Draw: {:x}", (uintptr_t)draw_native);

    // Set the first byte to the ret instruction
    m_overlay_draw_patch = Patch::create(draw_native, { 0xC3 });

    return std::nullopt;
}

int32_t VR::get_frame_count() const {
    auto scene = sdk::get_current_scene();

    if (scene == nullptr) {
        return 0;
    }

    return sdk::call_object_func<int32_t>(scene, "get_FrameCount", sdk::get_thread_context(), scene);

    /*static auto renderer_type = sdk::RETypeDB::get()->find_type("via.render.Renderer");
    auto renderer = g_framework->get_globals()->get_native("via.render.Renderer");

    if (renderer == nullptr) {
        return 0;
    }

    return sdk::call_object_func<int32_t>(renderer, renderer_type, "get_RenderFrame", sdk::get_thread_context(), renderer);*/
}

float VR::get_standing_height() {
    std::shared_lock _{ m_pose_mtx };

    return m_standing_origin.y;
}

Vector4f VR::get_standing_origin() {
    std::shared_lock _{ m_pose_mtx };

    return m_standing_origin;
}

Vector4f VR::get_current_offset() {
    if (!m_use_afr) {
        return Vector4f{};
    }

    std::shared_lock _{ m_eyes_mtx };

    if (get_frame_count() % 2 == 0) {
        //return Vector4f{m_eye_distance * -1.0f, 0.0f, 0.0f, 0.0f};
        return m_eyes[vr::Eye_Left][3];
    }
    
    return m_eyes[vr::Eye_Right][3];
    //return Vector4f{m_eye_distance, 0.0f, 0.0f, 0.0f};
}

Matrix4x4f VR::get_current_eye_transform() {
    if (!m_use_afr) {
        return glm::identity<Matrix4x4f>();
    }

    std::shared_lock _{m_eyes_mtx};

    const auto frame_count = get_frame_count();
    const auto flip = (m_frame_count < frame_count);

    if (get_frame_count() % 2 == 0) {
        return !flip ? m_eyes[vr::Eye_Left] : m_eyes[vr::Eye_Right];
    }

    return !flip ? m_eyes[vr::Eye_Right] : m_eyes[vr::Eye_Left];
}

Matrix4x4f VR::get_current_rotation_offset() {
    if (!m_use_afr) {
        return glm::identity<Matrix4x4f>();
    }

    return glm::extractMatrixRotation(get_current_eye_transform());
}

Matrix4x4f VR::get_current_projection_matrix(bool flip) {
    std::shared_lock _{m_eyes_mtx};

    auto mod_count = flip ? 1 : 0;

    if (get_frame_count() % 2 == mod_count) {
        return m_projections[vr::Eye_Left];
    }

    return m_projections[vr::Eye_Right];
}

void VR::on_post_frame() {
    //std::scoped_lock _{ m_camera_mtx };

    m_frame_count = get_frame_count();
    m_main_view = sdk::get_main_view();

    const auto renderer = g_framework->get_renderer_type();

    if (renderer == REFramework::RendererType::D3D11) {
        m_d3d11.on_frame(this);
    } else if (renderer == REFramework::RendererType::D3D12) {
        m_d3d12.on_frame(this);
    }

    m_last_frame_count = m_frame_count;

    if (m_submitted) {
        // Update input
        auto error = vr::VRInput()->UpdateActionState(&m_active_action_set, sizeof(m_active_action_set), 1);

        if (error != vr::VRInputError_None) {
            spdlog::error("VRInput failed to update action state: {}", (uint32_t)error);
        }

        vr::VRCompositor()->SetTrackingSpace(vr::TrackingUniverseStanding);
        vr::VRCompositor()->WaitGetPoses(m_real_render_poses.data(), vr::k_unMaxTrackedDeviceCount, m_real_game_poses.data(), vr::k_unMaxTrackedDeviceCount);

        bool wants_reset_origin = false;

        // Process events
        vr::VREvent_t event{};
        while (m_hmd->PollNextEvent(&event, sizeof(event))) {
            switch ((vr::EVREventType)event.eventType) {
                // Detect whether video settings changed
                case vr::VREvent_SteamVRSectionSettingChanged: {
                    spdlog::info("VR: VREvent_SteamVRSectionSettingChanged");
                    m_hmd->GetRecommendedRenderTargetSize(&m_w, &m_h);
                } break;

                // Detect whether SteamVR reset the standing/seated pose
                case vr::VREvent_SeatedZeroPoseReset: [[fallthrough]];
                case vr::VREvent_StandingZeroPoseReset: {
                    spdlog::info("VR: VREvent_SeatedZeroPoseReset");
                    wants_reset_origin = true;
                } break;

                default:
                    spdlog::info("VR: Unknown event: {}", (uint32_t)event.eventType);
                    break;
            }
        }

        // Update the poses used for the game
        // If we used the data directly from the WaitGetPoses call, we would have to lock a different mutex and wait a long time
        // This is because the WaitGetPoses call is blocking, and we don't want to block any game logic
        {
            std::unique_lock _{ m_pose_mtx };

            memcpy(m_game_poses.data(), m_real_game_poses.data(), sizeof(m_game_poses));
            memcpy(m_render_poses.data(), m_real_render_poses.data(), sizeof(m_render_poses));

            if (wants_reset_origin) {
                m_standing_origin = get_position_unsafe(vr::k_unTrackedDeviceIndex_Hmd);
            }
        }

        std::unique_lock __{ m_eyes_mtx };

        const auto local_left = m_hmd->GetEyeToHeadTransform(vr::Eye_Left);
        const auto local_right = m_hmd->GetEyeToHeadTransform(vr::Eye_Right);

        m_eyes[vr::Eye_Left] = glm::rowMajor4(Matrix4x4f{ *(Matrix3x4f*)&local_left } );
        m_eyes[vr::Eye_Right] = glm::rowMajor4(Matrix4x4f{ *(Matrix3x4f*)&local_right } );

        auto pleft = m_hmd->GetProjectionMatrix(vr::Eye_Left, m_nearz, m_farz);
        auto pright = m_hmd->GetProjectionMatrix(vr::Eye_Right, m_nearz, m_farz);

        m_projections[vr::Eye_Left] = glm::rowMajor4(Matrix4x4f{ *(Matrix4x4f*)&pleft } );
        m_projections[vr::Eye_Right] = glm::rowMajor4(Matrix4x4f{ *(Matrix4x4f*)&pright } );

        m_hmd->GetProjectionRaw(vr::Eye_Left, &m_raw_projections[vr::Eye_Left][0], &m_raw_projections[vr::Eye_Left][1], &m_raw_projections[vr::Eye_Left][2], &m_raw_projections[vr::Eye_Left][3]);
        m_hmd->GetProjectionRaw(vr::Eye_Right, &m_raw_projections[vr::Eye_Right][0], &m_raw_projections[vr::Eye_Right][1], &m_raw_projections[vr::Eye_Right][2], &m_raw_projections[vr::Eye_Right][3]);

        m_submitted = false;
    }
}

void VR::on_update_transform(RETransform* transform) {
    
}

void VR::on_update_camera_controller(RopewayPlayerCameraController* controller) {
    // get headset rotation
    /*const auto& headset_pose = m_game_poses[0];

    if (!headset_pose.bPoseIsValid) {
        return;
    }

    auto headset_matrix = Matrix4x4f{ *(Matrix3x4f*)&headset_pose.mDeviceToAbsoluteTracking };
    auto headset_rotation = glm::extractMatrixRotation(glm::rowMajor4(headset_matrix));

    headset_rotation *= get_current_rotation_offset();

    *(glm::quat*)&controller->worldRotation = glm::quat{ headset_rotation  };

    controller->worldPosition += get_current_offset();*/

    auto scene_view = sdk::get_main_view();
    auto camera = sdk::get_primary_camera();

    if (camera != nullptr) {
        // Fixes warping effect in the vertical part of the camera when looking up and down
        sdk::call_object_func<void*>((::REManagedObject*)camera, "set_VerticalEnable", sdk::get_thread_context(), camera, true);
        m_nearz = sdk::call_object_func<float>(camera, "get_NearClipPlane", sdk::get_thread_context(), camera);
        m_farz = sdk::call_object_func<float>(camera, "get_FarClipPlane", sdk::get_thread_context(), camera);
    }
}

struct GUIRestoreData {
    REComponent* element{nullptr};
    REComponent* view{nullptr};
    Vector4f original_position{ 0.0f, 0.0f, 0.0f, 1.0f };
    bool overlay{false};
    bool detonemap{true};
};

thread_local std::vector<std::unique_ptr<GUIRestoreData>> g_elements_to_reset{};

void VR::on_pre_gui_draw_element(REComponent* gui_element, void* primitive_context) {
    auto game_object = utility::re_component::get_game_object(gui_element);

    if (game_object != nullptr && game_object->transform != nullptr) {
        const auto name = utility::re_string::get_string(game_object->name);

        //spdlog::info("VR: on_pre_gui_draw_element: {}", name);

        auto view = sdk::call_object_func<REComponent*>(gui_element, "get_View", sdk::get_thread_context(), gui_element);

        if (view != nullptr) {
            const auto current_view_type = sdk::call_object_func<uint32_t>(view, "get_ViewType", sdk::get_thread_context(), view);

            if (current_view_type == (uint32_t)via::gui::ViewType::Screen) {
                auto& restore_data = g_elements_to_reset.emplace_back(std::make_unique<GUIRestoreData>());

                restore_data->element = gui_element;
                restore_data->view = view;
                restore_data->original_position = game_object->transform->worldTransform[3];
                restore_data->overlay = sdk::call_object_func<bool>(view, "get_Overlay", sdk::get_thread_context(), view);
                restore_data->detonemap = sdk::call_object_func<bool>(view, "get_Detonemap", sdk::get_thread_context(), view);

                // Set view type to world
                sdk::call_object_func<void*>(view, "set_ViewType", sdk::get_thread_context(), view, (uint32_t)via::gui::ViewType::World);

                // Set overlay = false (fixes double vision in VR)
                sdk::call_object_func<void*>(view, "set_Overlay", sdk::get_thread_context(), view, true);

                // Set detonemap = true (fixes weird tint)
                sdk::call_object_func<void*>(view, "set_Detonemap", sdk::get_thread_context(), view, true);

                // Go through the children until we hit a blur filter
                // And then remove it
                /*for (auto child = sdk::call_object_func<REComponent*>(view, "get_Child", sdk::get_thread_context(), view); child != nullptr; child = sdk::call_object_func<REComponent*>(child, "get_Child", sdk::get_thread_context(), child)) {
                    if (utility::re_managed_object::is_a(child, "via.gui.BlurFilter")) {
                        // Call remove()
                        sdk::call_object_func<void*>(child, "remove", sdk::get_thread_context(), child);
                        break;
                    }
                }*/

                auto camera = sdk::get_primary_camera();

                // Set the gui element's position to be in front of the camera
                if (camera != nullptr) {
                    auto camera_object = utility::re_component::get_game_object(camera);

                    if (camera_object != nullptr && camera_object->transform != nullptr) {
                        auto camera_transform = camera_object->transform;

                        const auto& camera_matrix = utility::re_transform::get_joint_matrix_by_index(*camera_transform, 0);
                        const auto& camera_position = camera_matrix[3];
                        
                        auto& gui_matrix = game_object->transform->worldTransform;

                        gui_matrix = glm::extractMatrixRotation(camera_matrix) * Matrix4x4f {
                            -1, 0, 0, 0,
                            0, 1, 0, 0,
                            0, 0, -1, 0,
                            0, 0, 0, 1
                        };
                        
                        gui_matrix[3] = camera_position + (-camera_matrix[2] * m_ui_scale);
                    }
                }
            }
        }
    } else {
        spdlog::info("VR: on_pre_gui_draw_element: nullptr gameobject");
    }
}

void VR::on_gui_draw_element(REComponent* gui_element, void* primitive_context) {
    //spdlog::info("VR: on_gui_draw_element");

    // Restore elements back to original states
    for (auto& data : g_elements_to_reset) {
        sdk::call_object_func<void*>(data->view, "set_ViewType", sdk::get_thread_context(), data->view, (uint32_t)via::gui::ViewType::Screen);
        sdk::call_object_func<void*>(data->view, "set_Overlay", sdk::get_thread_context(), data->view, data->overlay);
        sdk::call_object_func<void*>(data->view, "set_Detonemap", sdk::get_thread_context(), data->view, data->detonemap);
        
        auto game_object = utility::re_component::get_game_object(data->element);

        if (game_object != nullptr && game_object->transform != nullptr) {
            auto& gui_matrix = game_object->transform->worldTransform;

            gui_matrix[3] = data->original_position;
        }
    }

    g_elements_to_reset.clear();
}

void VR::openvr_input_to_game(REManagedObject* input_system) {
    // Get OpenVR input system
    auto openvr_input = vr::VRInput();

    if (openvr_input == nullptr) {
        spdlog::error("[VR] Failed to get OpenVR input system.");
        return;
    }

    auto lstick = sdk::call_object_func<REManagedObject*>(input_system, "get_LStick", sdk::get_thread_context());
    auto rstick = sdk::call_object_func<REManagedObject*>(input_system, "get_RStick", sdk::get_thread_context());

    if (lstick == nullptr || rstick == nullptr) {
        return;
    }

    auto button_bits_obj = sdk::call_object_func<REManagedObject*>(input_system, "get_ButtonBits", sdk::get_thread_context(), input_system);
    //auto button_bits_obj = utility::re_managed_object::get_field<REManagedObject*>(input_system, "ButtonBits");

    if (button_bits_obj == nullptr) {
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    auto is_using_controller = (now - get_last_controller_update()) <= std::chrono::seconds(10);

    const auto is_grip_down = is_action_active(m_action_grip, m_right_joystick);
    const auto is_trigger_down = is_action_active(m_action_trigger, m_right_joystick);
    const auto is_left_grip_down = is_action_active(m_action_grip, m_left_joystick);
    const auto is_left_trigger_down = is_action_active(m_action_trigger, m_left_joystick);
    const auto is_left_joystick_click_down = is_action_active(m_action_joystick_click, m_left_joystick);
    const auto is_right_joystick_click_down = is_action_active(m_action_joystick_click, m_right_joystick);

    const auto is_left_a_button_down = is_action_active(m_action_a_button, m_left_joystick);
    const auto is_left_b_button_down = is_action_active(m_action_b_button, m_left_joystick);
    const auto is_right_a_button_down = is_action_active(m_action_a_button, m_right_joystick);
    const auto is_right_b_button_down = is_action_active(m_action_b_button, m_right_joystick);

    // Current actual button bits used by the game
    auto& button_bits_down = *sdk::get_object_field<uint64_t>(button_bits_obj, "Down");
    auto& button_bits_on = *sdk::get_object_field<uint64_t>(button_bits_obj, "On");
    auto& button_bits_up = *sdk::get_object_field<uint64_t>(button_bits_obj, "Up");

    // Set button state based on our own history we keep that doesn't get overwritten by the game
    auto set_button_state = [&](app::ropeway::InputDefine::Kind kind, bool state) {
        const auto kind_uint64 = (uint64_t)kind;

        if (state) {
            m_last_controller_update = now;
            is_using_controller = true;

            button_bits_up &= ~kind_uint64;
            m_button_states_up &= ~kind_uint64;

            // if "On" state is not set
            if ((m_button_states_on.to_ullong() & kind_uint64) == 0) {
                if (m_button_states_down.to_ullong() & kind_uint64) {
                    m_button_states_on |= kind_uint64;
                    m_button_states_down &= ~kind_uint64;

                    button_bits_on |= kind_uint64;
                    button_bits_down &= ~kind_uint64;
                } else {
                    m_button_states_on &= ~kind_uint64;
                    m_button_states_down |= kind_uint64;

                    button_bits_on &= ~kind_uint64;
                    button_bits_down |= kind_uint64;
                }
            } else {
                m_button_states_down &= ~kind_uint64;
                button_bits_down &= ~kind_uint64;

                m_button_states_on |= kind_uint64;
                button_bits_on |= kind_uint64;
            }
        } else {
            if (m_button_states_down.to_ullong() & kind_uint64 || m_button_states_on.to_ullong() & kind_uint64) {
                m_button_states_up |= kind_uint64;
                button_bits_up |= kind_uint64;

                m_last_controller_update = now;
                is_using_controller = true;
            } else if (is_using_controller) {
                m_button_states_up &= ~kind_uint64;
                button_bits_up &= ~kind_uint64;
            }

            // Don't want to screw with the user's input if they aren't actively
            // Using their VR controllers
            if (is_using_controller) {
                button_bits_down &= ~kind_uint64;
                m_button_states_down &= ~kind_uint64;
                
                button_bits_on &= ~kind_uint64;
                m_button_states_on &= ~kind_uint64;
            }
        }
    };

    // Right Grip: Aim, UI Right (RB)
    set_button_state(app::ropeway::InputDefine::Kind::HOLD, is_grip_down);
    set_button_state(app::ropeway::InputDefine::Kind::UI_SHIFT_RIGHT, is_grip_down);

    // Left Grip: Alternate aim (grenades, knives, etc), UI left (LB)
    set_button_state(app::ropeway::InputDefine::Kind::SUPPORT_HOLD, is_left_grip_down);
    set_button_state(app::ropeway::InputDefine::Kind::UI_SHIFT_LEFT, is_left_grip_down);

    // Right Trigger (RB): Attack, Alternate UI right (RT), GE_RTrigBottom (quick time event), GE_RTrigTop (another quick time event)
    set_button_state(app::ropeway::InputDefine::Kind::ATTACK, is_trigger_down);
    set_button_state(app::ropeway::InputDefine::Kind::UI_SHIFT_RIGHT_2, is_trigger_down);
    set_button_state((app::ropeway::InputDefine::Kind)18014398509481984, is_trigger_down);
    set_button_state((app::ropeway::InputDefine::Kind)9007199254740992, is_trigger_down);
    //set_button_state((app::ropeway::InputDefine::Kind)4503599627370496, is_trigger_down);

    // Left Trigger (LB): Alternate UI left (LT)
    set_button_state(app::ropeway::InputDefine::Kind::UI_SHIFT_LEFT_2, is_left_trigger_down);

    // L3: Sprint
    set_button_state(app::ropeway::InputDefine::Kind::JOG1, is_left_joystick_click_down);

    // R3: Reset camera
    set_button_state(app::ropeway::InputDefine::Kind::RESET_CAMERA, is_right_joystick_click_down);

    // Left B: Inventory, PRESS_START
    set_button_state(app::ropeway::InputDefine::Kind::INVENTORY, is_left_b_button_down);
    set_button_state(app::ropeway::InputDefine::Kind::PRESS_START, is_left_b_button_down);

    // Left A: QUICK_TURN, PRESS_START, CANCEL, DIALOG_CANCEL
    set_button_state(app::ropeway::InputDefine::Kind::QUICK_TURN, is_left_a_button_down);
    set_button_state(app::ropeway::InputDefine::Kind::PRESS_START, is_left_a_button_down);
    set_button_state(app::ropeway::InputDefine::Kind::CANCEL, is_left_a_button_down);
    set_button_state(app::ropeway::InputDefine::Kind::DIALOG_CANCEL, is_left_a_button_down);
    
    // Right A: Action, ITEM, PRESS_START, DECIDE, DIALOG_DECIDE, (1 << 51)
    set_button_state(app::ropeway::InputDefine::Kind::ACTION, is_right_a_button_down);
    set_button_state(app::ropeway::InputDefine::Kind::ITEM, is_right_a_button_down);
    set_button_state(app::ropeway::InputDefine::Kind::PRESS_START, is_right_a_button_down);
    set_button_state(app::ropeway::InputDefine::Kind::DECIDE, is_right_a_button_down);
    set_button_state(app::ropeway::InputDefine::Kind::DIALOG_DECIDE, is_right_a_button_down);
    set_button_state((app::ropeway::InputDefine::Kind)((uint64_t)1 << 51), is_right_a_button_down);
    
    // Right B: Reload, Skip Event, UI_EXCHANGE, UI_RESET, (1 << 52) (that one is RE3 only? don't see it in the enum)
    set_button_state(app::ropeway::InputDefine::Kind::RELOAD, is_right_b_button_down);
    set_button_state(app::ropeway::InputDefine::Kind::SKIP_EVENT, is_right_b_button_down);
    set_button_state(app::ropeway::InputDefine::Kind::UI_EXCHANGE, is_right_b_button_down);
    set_button_state(app::ropeway::InputDefine::Kind::UI_RESET, is_right_b_button_down);
    set_button_state((app::ropeway::InputDefine::Kind)((uint64_t)1 << 52), is_right_b_button_down);

    const auto left_axis = get_left_stick_axis();
    const auto right_axis = get_right_stick_axis();
    const auto left_axis_len = glm::length(left_axis);
    const auto right_axis_len = glm::length(right_axis);

    bool moved_sticks = false;

    if (left_axis_len > CONTROLLER_DEADZONE) {
        moved_sticks = true;

        // Override the left stick's axis values to the VR controller's values
        Vector3f axis{ left_axis.x, left_axis.y, 0.0f };
        sdk::call_object_func<void*>(lstick, "update", sdk::get_thread_context(), lstick, &axis, &axis);
    }

    if (right_axis_len > CONTROLLER_DEADZONE) {
        moved_sticks = true;

        // Override the right stick's axis values to the VR controller's values
        Vector3f axis{ right_axis.x, right_axis.y, 0.0f };
        sdk::call_object_func<void*>(rstick, "update", sdk::get_thread_context(), rstick, &axis, &axis);
    }

    if (moved_sticks) {
        auto new_pos = get_position(vr::k_unTrackedDeviceIndex_Hmd);

        new_pos.y = m_standing_origin.y;
        // Don't set the Y because it would look really strange
        m_standing_origin = glm::lerp(m_standing_origin, new_pos, 1 / 90.0f);
    }

    set_button_state(app::ropeway::InputDefine::Kind::MOVE, left_axis_len > CONTROLLER_DEADZONE);
    set_button_state(app::ropeway::InputDefine::Kind::UI_L_STICK, left_axis_len > CONTROLLER_DEADZONE);

    set_button_state(app::ropeway::InputDefine::Kind::WATCH, right_axis_len > CONTROLLER_DEADZONE);
    set_button_state(app::ropeway::InputDefine::Kind::UI_R_STICK, right_axis_len > CONTROLLER_DEADZONE);
    //set_button_state(app::ropeway::InputDefine::Kind::RUN, right_axis_len > 0.01f);

    // Causes the right stick to take effect properly
    if (is_using_controller) {
        sdk::call_object_func<void*>(input_system, "set_InputMode", sdk::get_thread_context(), input_system, app::ropeway::InputDefine::InputMode::Pad);
    }
}

void VR::on_draw_ui() {
    // create VR tree entry in menu (imgui)
    ImGui::SetNextTreeNodeOpen(false, ImGuiCond_::ImGuiCond_FirstUseEver);

    if (!ImGui::CollapsingHeader(get_name().data())) {
        return;
    }

    // draw VR tree entry in menu (imgui)
    ImGui::Text("VR");
    ImGui::Separator();
    ImGui::Text("Recommended render target size: %d x %d", m_w, m_h);
    ImGui::Separator();
    ImGui::DragFloat4("Raw Left", (float*)&m_raw_projections[0], 0.01f, -100.0f, 100.0f);
    ImGui::DragFloat4("Raw Right", (float*)&m_raw_projections[1], 0.01f, -100.0f, 100.0f);
    ImGui::Separator();

    if (ImGui::Button("Set Standing Height")) {
        m_standing_origin.y = get_position(0).y;
    }

    ImGui::DragFloat4("Right Bounds", (float*)&m_right_bounds, 0.005f, -2.0f, 2.0f);
    ImGui::DragFloat4("Left Bounds", (float*)&m_left_bounds, 0.005f, -2.0f, 2.0f);
    ImGui::Checkbox("Use AFR", &m_use_afr);
    ImGui::Checkbox("Use Predicted Poses", &m_use_predicted_poses);
    ImGui::Checkbox("Use Eye Rotation", &m_use_rotation);
    ImGui::Checkbox("Invert Eye Rotation", &m_invert);
    ImGui::DragFloat("UI Scale", &m_ui_scale, 0.005f, 0.0f, 100.0f);
}

void VR::on_device_reset() {
    spdlog::info("VR: on_device_reset");
    m_d3d11.on_reset(this);
    m_d3d12.on_reset(this);
}

void VR::on_config_load(const utility::Config& cfg) {
    
}

void VR::on_config_save(utility::Config& cfg) {
    
}

Vector4f VR::get_position(uint32_t index) {
    if (index >= vr::k_unMaxTrackedDeviceCount) {
        return Vector4f{};
    }

    std::shared_lock _{ m_pose_mtx };

    return get_position_unsafe(index);
}

Vector4f VR::get_position_unsafe(uint32_t index) {
    if (index >= vr::k_unMaxTrackedDeviceCount) {
        return Vector4f{};
    }

    auto& pose = get_poses()[index];
    auto matrix = Matrix4x4f{ *(Matrix3x4f*)&pose.mDeviceToAbsoluteTracking };
    auto result = glm::rowMajor4(matrix)[3];
    result.w = 1.0f;

    return result;
}

Matrix4x4f VR::get_rotation(uint32_t index) {
    if (index >= vr::k_unMaxTrackedDeviceCount) {
        return glm::identity<Matrix4x4f>();
    }

    std::shared_lock _{ m_pose_mtx };

    auto& pose = get_poses()[index];
    auto matrix = Matrix4x4f{ *(Matrix3x4f*)&pose.mDeviceToAbsoluteTracking };
    return glm::extractMatrixRotation(glm::rowMajor4(matrix));
}

bool VR::is_action_active(vr::VRActionHandle_t action, vr::VRInputValueHandle_t source) const {
    vr::InputDigitalActionData_t data{};
	vr::VRInput()->GetDigitalActionData(action, &data, sizeof(data), source);

    return data.bActive && data.bState;
}

Vector2f VR::get_joystick_axis(vr::VRInputValueHandle_t handle) const {
    vr::InputAnalogActionData_t data{};
    vr::VRInput()->GetAnalogActionData(m_action_joystick, &data, sizeof(data), handle);

    return Vector2f{ data.x, data.y };
}

Vector2f VR::get_left_stick_axis() const {
    return get_joystick_axis(m_left_joystick);
}

Vector2f VR::get_right_stick_axis() const {
    return get_joystick_axis(m_right_joystick);
}