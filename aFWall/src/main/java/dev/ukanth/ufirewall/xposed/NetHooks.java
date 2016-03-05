package dev.ukanth.ufirewall.xposed;

/**
 * Created by ukanth on 1/3/16.
 */

import java.net.URL;
import java.net.URLStreamHandler;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import static de.robv.android.xposed.XposedHelpers.findAndHookConstructor;

public class NetHooks implements IXposedHookLoadPackage {

    private static String Tag = "afwallmon";

    //set targetPackage to a specific application, leave empty to target all
    String targetPackage = "";
    String packageName = null;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {

        packageName = lpparam.packageName;

        if (!targetPackage.isEmpty() && !targetPackage.equals(packageName))
            return;


        findAndHookConstructor("java.net.InetAddress", lpparam.classLoader, String.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                XposedBridge.log("URLSniffer: " + packageName + " Spec: " + param.args[0]);

            }

        });

        findAndHookConstructor("java.net.InetAddress", lpparam.classLoader, URL.class, String.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                XposedBridge.log("URLSniffer: " + packageName + " Spec: " + param.args[1]);

            }

        });

        findAndHookConstructor("java.net.InetAddress", lpparam.classLoader, URL.class, String.class, URLStreamHandler.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                XposedBridge.log("URLSniffer: " + packageName + " Spec: " + param.args[1]);

            }

        });

        findAndHookConstructor("java.net.InetAddress", lpparam.classLoader, String.class, String.class, String.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                XposedBridge.log("URLSniffer: " + packageName + " Protocol: " + param.args[0] + " Host: " + param.args[1] + " File: " + param.args[2]);

            }

        });

        findAndHookConstructor("java.net.InetAddress", lpparam.classLoader, String.class, String.class, int.class, String.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                XposedBridge.log("URLSniffer: " + packageName + " Protocol: " + param.args[0] + " Host: " + param.args[1] + " Port: " + Integer.toString((Integer) param.args[2]) + " File: " + param.args[3]);

            }

        });
        findAndHookConstructor("java.net.InetAddress", lpparam.classLoader, String.class, String.class, int.class, String.class, URLStreamHandler.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                XposedBridge.log("URLSniffer: " + packageName + " Protocol: " + param.args[0] + " Host: " + param.args[1] + " Port: " + Integer.toString((Integer) param.args[2]) + " File: " + param.args[3]);

            }

        });
    }

}