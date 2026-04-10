/**
 * App framework detection.
 *
 * Inspects an app bundle's Frameworks directory, files, and linked libraries
 * to detect cross-platform frameworks, game engines, and system frameworks.
 */

import * as fs from "fs";
import * as path from "path";

export function detectAppFrameworks(appBundlePath: string, linkedLibs: string[] = []): string[] {
  const frameworksDir = path.join(appBundlePath, "Frameworks");
  const detected: string[] = [];

  const hasFramework = (name: string): boolean => {
    try {
      return fs.existsSync(path.join(frameworksDir, name));
    } catch {
      return false;
    }
  };

  const hasFile = (relPath: string): boolean => {
    try {
      return fs.existsSync(path.join(appBundlePath, relPath));
    } catch {
      return false;
    }
  };

  const hasAnyFramework = (...names: string[]): boolean =>
    names.some(hasFramework);

  /** Check if the binary links against a system framework by name */
  const linksFramework = (name: string): boolean =>
    linkedLibs.some((lib) => lib.includes(`/${name}.framework/`));

  // ── Cross-platform frameworks ──

  // React Native
  if (
    hasFile("main.jsbundle") ||
    hasAnyFramework("hermes.framework", "React.framework", "ReactNative.framework")
  ) {
    detected.push("React Native");
  }

  // Expo (built on React Native)
  if (hasAnyFramework("ExpoModulesCore.framework", "Expo.framework")) {
    detected.push("Expo");
  }

  // Flutter (iOS uses Flutter.framework, macOS uses FlutterMacOS.framework)
  if (hasAnyFramework("Flutter.framework", "FlutterMacOS.framework")) {
    detected.push("Flutter");
  }

  // Cordova
  if (hasFile("www/index.html") && !hasFramework("Capacitor.framework")) {
    detected.push("Cordova");
  }

  // Capacitor
  if (hasFramework("Capacitor.framework") || hasFramework("CapacitorBridge.framework")) {
    detected.push("Capacitor");
  }

  // .NET MAUI / Xamarin
  if (hasAnyFramework("Xamarin.iOS.framework", "Mono.framework")) {
    detected.push("Xamarin/.NET MAUI");
  }

  // Kotlin Multiplatform
  if (hasAnyFramework("shared.framework") && hasFramework("KotlinRuntime.framework")) {
    detected.push("Kotlin Multiplatform");
  }

  // NativeScript
  if (hasAnyFramework("NativeScript.framework", "TNSRuntime.framework")) {
    detected.push("NativeScript");
  }

  // Titanium / Appcelerator
  if (hasAnyFramework("TitaniumKit.framework", "Titanium.framework")) {
    detected.push("Titanium");
  }

  // Qt
  if (hasAnyFramework("QtCore.framework", "Qt.framework")) {
    detected.push("Qt");
  }

  // Electron (very rare on iOS, but included for completeness)
  if (hasFramework("Electron Framework.framework")) {
    detected.push("Electron");
  }

  // ── Game engines ──

  // Unity
  if (hasFramework("UnityFramework.framework")) {
    detected.push("Unity");
  }

  // Unreal Engine
  if (hasAnyFramework("UE4.framework", "UnrealEngine.framework") || hasFile("UE4CommandLine.txt") || hasFile("uecommandline.txt")) {
    detected.push("Unreal Engine");
  }

  // Godot
  if (hasFile("godot_ios.pck")) {
    detected.push("Godot");
  }

  // Cocos2d
  if (hasAnyFramework("cocos2d.framework", "cocos2d_libs.framework")) {
    detected.push("Cocos2d");
  }

  // GameMaker
  if (hasFile("game.ios") || hasFile("data.win")) {
    detected.push("GameMaker");
  }

  // Corona / Solar2D
  if (hasAnyFramework("CoronaKit.framework", "Corona.framework")) {
    detected.push("Solar2D");
  }

  // ── Linked system frameworks (not bundled, detected via load commands) ──

  const systemFrameworks: string[] = [
    // UI layer
    "SwiftUI", "UIKit", "AppKit",
    // Graphics & games
    "RealityKit", "ARKit", "SceneKit", "SpriteKit", "Metal", "GameKit"
  ];

  for (const framework of systemFrameworks) {
    if (linksFramework(framework)) {
      detected.push(framework);
    }
  }

  return detected;
}
