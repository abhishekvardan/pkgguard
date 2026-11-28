export declare function notifyCommand(platform?: NodeJS.Platform): {
    cmd: string;
    args: string[];
} | undefined;
export declare function notify(title: string, body: string): boolean;
