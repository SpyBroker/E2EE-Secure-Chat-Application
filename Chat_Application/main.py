"""
Launcher. Runs the app; if it crashes on startup, the error is shown on screen
and saved to crash_log.txt so problems on a phone can be diagnosed.
"""
import os
import traceback


def _fix_pythonapi():
    """Android fix: on python-for-android, ctypes.pythonapi (dlopen(NULL)) can't see
    libpython's symbols, which breaks pycryptodome ('undefined symbol: PyObject_GetBuffer').
    Point it at the real libpython before pycryptodome is imported."""
    import ctypes

    def works():
        try:
            ctypes.pythonapi.PyObject_GetBuffer
            return True
        except AttributeError:
            return False

    if works():
        return
    import sys
    ver = "%d.%d" % sys.version_info[:2]
    candidates = ["libpython%s.so" % ver, "libpython%s.so.1.0" % ver]
    try:
        with open("/proc/self/maps") as f:
            for line in f:
                path = line.split()[-1]
                if "libpython" in path and ".so" in path and path not in candidates:
                    candidates.insert(0, path)
    except Exception:
        pass
    for name in candidates:
        try:
            api = ctypes.PyDLL(name)
            api.PyObject_GetBuffer
            ctypes.pythonapi = api
            print("pythonapi fixed using", name, flush=True)
            return
        except Exception:
            continue
    print("WARNING: could not repair ctypes.pythonapi", flush=True)


try:
    _fix_pythonapi()
except Exception:
    pass


def _report(tb):
    print(tb, flush=True)  # also visible in `adb logcat`
    try:
        from kivy.app import App
        from kivy.core.window import Window
        from kivy.uix.label import Label
        from kivy.uix.scrollview import ScrollView

        class CrashApp(App):
            def build(self):
                try:
                    with open(os.path.join(self.user_data_dir, "crash_log.txt"), "w") as f:
                        f.write(tb)
                except Exception:
                    pass
                sv = ScrollView()
                lbl = Label(text="E2EE Chat crashed on startup (launcher v2):\n\n" + tb, font_size="12sp",
                            size_hint_y=None, halign="left", valign="top",
                            text_size=(Window.width - 20, None))
                lbl.bind(texture_size=lambda i, s: setattr(i, "height", s[1] + 40))
                sv.add_widget(lbl)
                return sv

        CrashApp().run()
    except Exception:
        pass


try:
    from app_main import E2EEChatApp
    E2EEChatApp().run()
except Exception:
    _report(traceback.format_exc())