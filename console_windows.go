//go:build windows

package main

import "syscall"

// hideConsoleWindow hides the console window of the current process. Useful
// when launched from Explorer / Task Scheduler so users don't see a black box.
// All log output already goes to the file + in-memory ring, so we lose nothing.
func hideConsoleWindow() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	user32 := syscall.NewLazyDLL("user32.dll")
	getConsoleWindow := kernel32.NewProc("GetConsoleWindow")
	showWindow := user32.NewProc("ShowWindow")
	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd != 0 {
		const SW_HIDE = 0
		showWindow.Call(hwnd, SW_HIDE)
	}
}
