"""
E2EE Chat - Kivy mobile app.
Place next to mobile_client.py, storage.py, protocol.py, crypto.py (inside Chat_Application/).
Run on desktop:  python main.py
"""
import os
import json
import time
import sqlite3
import threading
import socket

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.graphics import Color, RoundedRectangle
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import StringProperty, BooleanProperty, ListProperty
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.dropdown import DropDown
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import Screen
from kivy.uix.textinput import TextInput
from kivy.uix.widget import Widget
from kivy.utils import platform, escape_markup

from mobile_client import MobileChatClient
from storage import validate_phone_number

GREEN = (0.45, 1, 0.55, 1)
RED = (1, 0.55, 0.55, 1)
ORANGE = (1, 0.8, 0.4, 1)
WHITE = (1, 1, 1, 0.8)
DEFAULT_CFG = {"host": "127.0.0.1", "port": 65432, "phone": "", "idle_minutes": 5}
MAGIC = [(b"%PDF", ".pdf"), (b"\x89PNG", ".png"), (b"\xff\xd8\xff", ".jpg"),
         (b"GIF8", ".gif"), (b"PK\x03\x04", ".zip")]

KV = """
#:import NoTransition kivy.uix.screenmanager.NoTransition

<DotsButton>:
    size_hint: None, 1
    width: dp(48)
    canvas:
        Color:
            rgba: 1, 1, 1, 1
        Ellipse:
            pos: self.center_x - dp(2.5), self.center_y + dp(8)
            size: dp(5), dp(5)
        Ellipse:
            pos: self.center_x - dp(2.5), self.center_y - dp(2.5)
            size: dp(5), dp(5)
        Ellipse:
            pos: self.center_x - dp(2.5), self.center_y - dp(13)
            size: dp(5), dp(5)

<Root>:
    orientation: 'vertical'
    BoxLayout:
        size_hint_y: None
        height: dp(56)
        padding: dp(4), 0
        canvas.before:
            Color:
                rgba: 0.07, 0.35, 0.45, 1
            Rectangle:
                pos: self.pos
                size: self.size
        Button:
            text: '<'
            size_hint_x: None
            width: dp(44) if app.can_go_back else 0
            opacity: 1 if app.can_go_back else 0
            disabled: not app.can_go_back
            background_color: 0, 0, 0, 0
            font_size: dp(24)
            on_release: app.go_back()
        BoxLayout:
            orientation: 'vertical'
            padding: dp(8), 0
            Label:
                text: app.title_text
                bold: True
                font_size: dp(18)
                halign: 'left'
                valign: 'bottom'
                text_size: self.size
            Label:
                text: app.status_text
                font_size: dp(12)
                color: app.status_color
                halign: 'left'
                valign: 'top'
                text_size: self.size
        DotsButton:
            on_release: app.open_menu(self)
    ScreenManager:
        id: sm
        transition: NoTransition()
        LoginScreen:
        ChatsScreen:
        ChatScreen:

<LoginScreen>:
    name: 'login'
    BoxLayout:
        orientation: 'vertical'
        padding: dp(24)
        spacing: dp(12)
        Widget:
        Label:
            text: 'Secure E2EE Chat'
            font_size: dp(26)
            size_hint_y: None
            height: dp(50)
        Label:
            text: 'Enter your 10-digit phone number'
            size_hint_y: None
            height: dp(28)
        TextInput:
            id: phone
            hint_text: '9876543210'
            multiline: False
            input_type: 'number'
            size_hint_y: None
            height: dp(48)
            font_size: dp(18)
            write_tab: False
            on_text_validate: app.login(self.text)
        Button:
            text: 'Connect'
            size_hint_y: None
            height: dp(50)
            on_release: app.login(phone.text)
        Label:
            text: app.hint
            color: 1, 0.8, 0.5, 1
            text_size: self.width, None
            halign: 'center'
            size_hint_y: None
            height: dp(70)
        Label:
            text: 'Tip: open the menu (three dots, top right) > Config to set the server IP and port first.'
            font_size: dp(12)
            color: 1, 1, 1, 0.55
            text_size: self.width, None
            halign: 'center'
            size_hint_y: None
            height: dp(40)
        Widget:

<ChatsScreen>:
    name: 'chats'
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
            GridLayout:
                id: list
                cols: 1
                size_hint_y: None
                height: self.minimum_height
                spacing: dp(2)
        BoxLayout:
            size_hint_y: None
            height: dp(52)
            padding: dp(6)
            spacing: dp(6)
            TextInput:
                id: newphone
                hint_text: 'Phone number to chat with'
                multiline: False
                input_type: 'number'
                write_tab: False
                on_text_validate: app.start_chat(self.text)
            Button:
                text: 'New chat'
                size_hint_x: None
                width: dp(100)
                on_release: app.start_chat(newphone.text)

<ChatScreen>:
    name: 'chat'
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
            id: sv
            GridLayout:
                id: msgs
                cols: 1
                size_hint_y: None
                height: self.minimum_height
                spacing: dp(2)
                padding: 0, dp(6)
        BoxLayout:
            size_hint_y: None
            height: dp(52)
            padding: dp(6)
            spacing: dp(6)
            Button:
                text: '+'
                font_size: dp(24)
                size_hint_x: None
                width: dp(48)
                on_release: app.pick_file()
            TextInput:
                id: inp
                hint_text: 'Type a message (E2EE)'
                multiline: False
                write_tab: False
                on_text_validate: app.send()
            Button:
                text: 'Send'
                size_hint_x: None
                width: dp(76)
                on_release: app.send()
"""


class DotsButton(ButtonBehavior, Widget):
    pass


class Root(BoxLayout):
    pass


class LoginScreen(Screen):
    pass


class ChatsScreen(Screen):
    pass


class ChatScreen(Screen):
    pass


class Bubble(BoxLayout):
    def __init__(self, text, outgoing, ts=None, **kw):
        super().__init__(size_hint_y=None, height=dp(44), padding=(dp(8), dp(3)), **kw)
        shown = escape_markup(text)
        if ts:
            shown += "\n[size=11sp][color=b0b0b0]%s[/color][/size]" % time.strftime(
                "%d %b %H:%M", time.localtime(ts))
        lbl = Label(text=shown, markup=True, size_hint=(None, None), halign="left",
                    valign="top", text_size=(Window.width * 0.7, None))

        def fit(inst, ts):
            inst.size = (ts[0] + dp(20), ts[1] + dp(14))
            self.height = inst.height + dp(6)

        lbl.bind(texture_size=fit)
        with lbl.canvas.before:
            Color(*((0.05, 0.45, 0.35, 1) if outgoing else (0.2, 0.22, 0.27, 1)))
            rect = RoundedRectangle(radius=[dp(12)])
        lbl.bind(pos=lambda i, v: setattr(rect, "pos", v),
                 size=lambda i, v: setattr(rect, "size", v))
        if outgoing:
            self.add_widget(Widget())
        self.add_widget(lbl)
        if not outgoing:
            self.add_widget(Widget())


class E2EEChatApp(App):
    title_text = StringProperty("E2EE Chat")
    status_text = StringProperty("Not connected")
    status_color = ListProperty(WHITE)
    can_go_back = BooleanProperty(False)
    hint = StringProperty("")

    # ------------------------------------------------------------ setup
    def build(self):
        Window.clearcolor = (0.08, 0.09, 0.11, 1)
        Window.softinput_mode = "below_target"
        self.cfg_path = os.path.join(self.user_data_dir, "config.json")
        self.cache_dir = os.path.join(self.user_data_dir, "device_cache")
        self.cfg = self._load_cfg()
        self.client = None
        self.phone = None
        self.peer = None
        self.connecting = False
        self.want_online = False
        self.last_activity = time.time()
        Window.bind(on_touch_down=self._touch, on_key_down=self._key)
        Clock.schedule_interval(self._watchdog, 4)
        return Root()

    def on_start(self):
        self.sm = self.root.ids.sm
        self.sm.get_screen("login").ids.phone.text = self.cfg.get("phone", "")
        if platform == "android":
            try:
                from android.permissions import request_permissions, Permission
                request_permissions([Permission.READ_EXTERNAL_STORAGE,
                                     Permission.WRITE_EXTERNAL_STORAGE])
            except Exception:
                pass

    def on_stop(self):
        self._hard_close(self.client)

    def on_pause(self):
        return True  # keep app alive on Android; idle timer keeps counting

    def on_resume(self):
        self._watchdog(0)  # enforce idle timeout immediately after returning

    # ------------------------------------------------------------ idle handling
    def _touch(self, *args):
        self.last_activity = time.time()

    def _key(self, *args):
        self.last_activity = time.time()

    def _idle_limit(self):
        try:
            return float(self.cfg.get("idle_minutes", 5)) * 60
        except (TypeError, ValueError):
            return 300.0

    @staticmethod
    def _hard_close(client):
        """shutdown() before close() so the server really sees the connection drop,
        even while the listener thread is blocked in recv()."""
        if not client:
            return
        client._running = False
        try:
            client.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        client.close()

    # ------------------------------------------------------------ config
    def _load_cfg(self):
        cfg = dict(DEFAULT_CFG)
        try:
            with open(self.cfg_path, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
        return cfg

    def _save_cfg(self):
        os.makedirs(self.user_data_dir, exist_ok=True)
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump(self.cfg, f)

    def hosts(self):
        return [h.strip() for h in str(self.cfg["host"]).split(",") if h.strip()]

    def set_status(self, text, color=WHITE):
        self.status_text = text
        self.status_color = color

    # ------------------------------------------------------------ menu
    def open_menu(self, caller):
        dd = DropDown(auto_width=False, width=dp(180))
        items = [("Config", self.open_config)]
        if self.phone:
            items += [("Reconnect", self.reconnect), ("Logout", self.logout)]
        for text, fn in items:
            b = Button(text=text, size_hint_y=None, height=dp(46))
            b.bind(on_release=lambda i, f=fn: (dd.dismiss(), f()))
            dd.add_widget(b)
        dd.open(caller)

    def open_config(self):
        box = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(10))
        box.add_widget(Label(text="Server IP (comma-separate several)",
                             size_hint_y=None, height=dp(24)))
        host = TextInput(text=str(self.cfg["host"]), multiline=False,
                         size_hint_y=None, height=dp(44), write_tab=False)
        box.add_widget(host)
        box.add_widget(Label(text="Port", size_hint_y=None, height=dp(24)))
        port = TextInput(text=str(self.cfg["port"]), multiline=False, input_filter="int",
                         size_hint_y=None, height=dp(44), write_tab=False)
        box.add_widget(port)
        box.add_widget(Label(text="Disconnect after idle (minutes, 0 = never)",
                             size_hint_y=None, height=dp(24)))
        idle = TextInput(text=str(self.cfg.get("idle_minutes", 5)), multiline=False,
                         input_filter="int", size_hint_y=None, height=dp(44), write_tab=False)
        box.add_widget(idle)
        msg = Label(text="", color=RED, size_hint_y=None, height=dp(24))
        box.add_widget(msg)
        row = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        cancel, save = Button(text="Cancel"), Button(text="Save")
        row.add_widget(cancel)
        row.add_widget(save)
        box.add_widget(row)
        pop = Popup(title="Config", content=box, size_hint=(0.92, None), height=dp(430))

        def do_save(*_):
            hosts = [h.strip() for h in host.text.split(",") if h.strip()]
            try:
                p = int(port.text)
                if not 1 <= p <= 65535:
                    raise ValueError
            except ValueError:
                msg.text = "Port must be 1-65535"
                return
            if not hosts:
                msg.text = "Enter at least one IP"
                return
            self.cfg["idle_minutes"] = int(idle.text or 0)
            self.cfg["host"], self.cfg["port"] = ",".join(hosts), p
            self._save_cfg()
            pop.dismiss()
            if self.phone:
                self.reconnect()
            else:
                self.hint = "Config saved. Tap Connect."

        cancel.bind(on_release=pop.dismiss)
        save.bind(on_release=do_save)
        pop.open()

    # ------------------------------------------------------------ connection
    def login(self, phone_raw):
        try:
            phone = validate_phone_number(phone_raw)
        except ValueError as e:
            self.hint = str(e)
            return
        self.cfg["phone"] = phone
        self._save_cfg()
        self.last_activity = time.time()
        self.hint = "Connecting... first login generates RSA-3072 keys and can take a while."
        self.want_online = True
        self.connect(phone)

    def connect(self, phone):
        if self.connecting:
            return
        self.connecting = True
        self.set_status("Connecting...", ORANGE)
        hosts, port, old = self.hosts(), int(self.cfg["port"]), self.client

        def work():
            client, err = None, None
            try:
                self._hard_close(old)
                client = MobileChatClient(host=hosts, port=port, cache_dir=self.cache_dir)
                client.on_message_received = self._cb_message
                client.on_file_received = self._cb_file
                client.on_connection_status = self._cb_status
                if not client.login_and_connect(phone):
                    err = "Could not reach server. Check IP/port in Config."
            except Exception as e:
                err = str(e)
            Clock.schedule_once(lambda dt: self._after_connect(client, phone, err))

        threading.Thread(target=work, daemon=True).start()

    def _after_connect(self, client, phone, err):
        self.connecting = False
        if err:
            self.set_status("Offline", RED)
            self.hint = err
            return
        self.client, self.phone = client, phone
        self.last_activity = time.time()
        self.hint = ""
        self.set_status("Connected as " + phone, GREEN)
        if self.sm.current == "login":
            self.title_text = "Chats"
            self.sm.current = "chats"
            self.refresh_chats()

    def _watchdog(self, dt):
        if not self.want_online or self.connecting or not self.phone:
            return
        limit = self._idle_limit()
        if limit > 0 and time.time() - self.last_activity > limit:
            mins = int(limit // 60) if limit >= 60 else limit
            self.logout()
            self.hint = ("Disconnected after %s minute(s) of inactivity. "
                         "Tap Connect to sign in again." % mins)
            return
        if self.client is None or not self.client._running:
            self.set_status("Offline - retrying...", RED)
            self.connect(self.phone)

    def reconnect(self):
        if self.phone:
            self.want_online = True
            self.connect(self.phone)

    def logout(self):
        self.want_online = False
        self._hard_close(self.client)
        self.client = self.phone = self.peer = None
        self.can_go_back = False
        self.title_text = "E2EE Chat"
        self.set_status("Not connected")
        self.sm.current = "login"

    # ------------------------------------------------------------ callbacks (listener thread)
    def _cb_status(self, info):
        def ui(dt):
            st = info.get("status")
            if st == "error":
                self.set_status("Error: " + str(info.get("message", "")), RED)
            elif st == "delivered":
                self.set_status("Delivered to " + str(info.get("receiverID", "")), GREEN)
            elif st == "queued":
                self.set_status("Recipient offline - queued", ORANGE)
            elif st == "connected":
                self.set_status("Connected as " + str(info.get("phone_number", "")), GREEN)
        Clock.schedule_once(ui)

    def _cb_message(self, sender, text, is_e2ee):
        Clock.schedule_once(lambda dt: self._incoming(sender))

    def _cb_file(self, sender, data, is_e2ee):
        if not data:
            return
        ext = next((e for m, e in MAGIC if data.startswith(m)), ".bin")
        name = "%s_%d%s" % (sender, int(time.time()), ext)
        folder = self._received_dir()
        path = os.path.join(folder, name)
        try:
            with open(path, "wb") as f:
                f.write(data)
        except OSError:
            folder = os.path.join(self.user_data_dir, "received_files")
            os.makedirs(folder, exist_ok=True)
            path = os.path.join(folder, name)
            with open(path, "wb") as f:
                f.write(data)
        if self.client and self.client.chat_db:
            self.client.chat_db.save_message(sender, "incoming", "[file] saved to " + path,
                                             content_type="file")
        Clock.schedule_once(lambda dt: self._incoming(sender))

    def _received_dir(self):
        base = self.user_data_dir
        if platform == "android":
            try:
                from android.storage import primary_external_storage_path
                base = os.path.join(primary_external_storage_path(), "Download")
            except Exception:
                pass
        d = os.path.join(base, "E2EEChat_received")
        try:
            os.makedirs(d, exist_ok=True)
            return d
        except OSError:
            d = os.path.join(self.user_data_dir, "received_files")
            os.makedirs(d, exist_ok=True)
            return d

    def _incoming(self, sender):
        if self.sm.current == "chat" and self.peer == sender:
            self.refresh_chat()
        else:
            self.set_status("New message from " + sender, GREEN)
            if self.sm.current == "chats":
                self.refresh_chats()

    # ------------------------------------------------------------ chats list
    def refresh_chats(self):
        box = self.sm.get_screen("chats").ids.list
        box.clear_widgets()
        rows = []
        if self.client and self.client.chat_db:
            try:
                with sqlite3.connect(self.client.chat_db.db_path) as conn:
                    rows = conn.execute(
                        "SELECT peer_phone, body, MAX(timestamp) FROM messages "
                        "GROUP BY peer_phone ORDER BY MAX(timestamp) DESC").fetchall()
            except sqlite3.Error:
                rows = []
        for peer, body, ts in rows:
            when = time.strftime("%d %b %H:%M", time.localtime(ts))
            b = Button(text="%s  (%s)\n%s" % (peer, when, body.replace("\n", " ")[:40]),
                       size_hint_y=None, height=dp(64), halign="left",
                       background_normal="", background_color=(0.12, 0.14, 0.17, 1))
            b.bind(size=lambda i, s: setattr(i, "text_size", (s[0] - dp(20), s[1])))
            b.bind(on_release=lambda i, p=peer: self.open_chat(p))
            box.add_widget(b)
        if not rows:
            box.add_widget(Label(text="No chats yet. Enter a number below to start.",
                                 size_hint_y=None, height=dp(80)))

    def start_chat(self, raw):
        try:
            peer = validate_phone_number(raw)
        except ValueError as e:
            self.set_status(str(e), RED)
            return
        self.sm.get_screen("chats").ids.newphone.text = ""
        self.open_chat(peer)

    def open_chat(self, peer):
        self.peer = peer
        self.title_text = peer
        self.can_go_back = True
        self.sm.current = "chat"
        self.refresh_chat()

    def go_back(self):
        if self.sm.current == "chat":
            self.peer = None
            self.can_go_back = False
            self.title_text = "Chats"
            self.sm.current = "chats"
            self.refresh_chats()

    # ------------------------------------------------------------ chat screen
    def refresh_chat(self):
        scr = self.sm.get_screen("chat")
        scr.ids.msgs.clear_widgets()
        for m in self._history(self.peer):
            scr.ids.msgs.add_widget(Bubble(m["body"], m["direction"] == "outgoing", m["timestamp"]))
        Clock.schedule_once(lambda dt: setattr(scr.ids.sv, "scroll_y", 0), 0.1)

    def _history(self, peer, limit=500):
        """Latest `limit` messages for this peer, oldest first (full local history)."""
        if not (self.client and self.client.chat_db and peer):
            return []
        try:
            with sqlite3.connect(self.client.chat_db.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM (SELECT * FROM messages WHERE peer_phone=? "
                    "ORDER BY timestamp DESC LIMIT ?) ORDER BY timestamp ASC",
                    (peer, limit)).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error:
            return []

    def _ready(self):
        if not self.client or not self.client._running:
            self.set_status("Offline - check Config", RED)
            return False
        return True

    def send(self):
        inp = self.sm.get_screen("chat").ids.inp
        text, peer = inp.text.strip(), self.peer
        if not text or not peer or not self._ready():
            return
        inp.text = ""
        self.last_activity = time.time()

        def work():
            err = None
            try:
                self.client.send_secure_message(peer, text)
            except Exception as e:
                err = str(e)
            Clock.schedule_once(lambda dt: self._after_send(peer, err, text))

        threading.Thread(target=work, daemon=True).start()

    def _after_send(self, peer, err, text=""):
        if err:
            if "public key" in err:
                err = "Recipient has not registered yet"
            self.set_status(err, RED)
            if self.peer == peer:
                self.sm.get_screen("chat").ids.inp.text = text
        elif self.peer == peer:
            self.refresh_chat()

    def pick_file(self):
        if not self.peer or not self._ready():
            return
        start = os.path.expanduser("~")
        if platform == "android":
            try:
                from android.storage import primary_external_storage_path
                start = primary_external_storage_path()
            except Exception:
                pass
        box = BoxLayout(orientation="vertical", spacing=dp(6))
        fc = FileChooserListView(path=start)
        row = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(8))
        cancel, ok = Button(text="Cancel"), Button(text="Send file")
        row.add_widget(cancel)
        row.add_widget(ok)
        box.add_widget(fc)
        box.add_widget(row)
        pop = Popup(title="Choose a file", content=box, size_hint=(0.95, 0.9))

        def go(*_):
            if fc.selection:
                pop.dismiss()
                self._send_file(fc.selection[0])

        cancel.bind(on_release=pop.dismiss)
        ok.bind(on_release=go)
        pop.open()

    def _send_file(self, path):
        peer = self.peer
        self.set_status("Sending file...", ORANGE)

        def work():
            err = None
            try:
                self.client.send_secure_file(peer, path)
                self.client.chat_db.save_message(
                    peer, "outgoing", "[file] sent: " + os.path.basename(path),
                    content_type="file")
            except Exception as e:
                err = str(e)
            Clock.schedule_once(lambda dt: self._after_send(peer, err))

        threading.Thread(target=work, daemon=True).start()


Builder.load_string(KV)

if __name__ == "__main__":
    E2EEChatApp().run()
