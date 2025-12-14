"use client";

import { ShieldCheck } from "lucide-react";

export function Navbar() {
    return (
        <header className="fixed top-0 w-full z-50 border-b border-white/10 bg-slate-950/80 backdrop-blur-md">
            <div className="flex h-16 items-center justify-between px-6 max-w-7xl mx-auto">
                <div className="flex items-center gap-2 font-bold text-xl">
                    <ShieldCheck className="text-emerald-500 w-6 h-6" />
                    <span>SecureScan<span className="text-emerald-500">.Lite</span></span>
                </div>
            </div>
        </header>
    );
}
