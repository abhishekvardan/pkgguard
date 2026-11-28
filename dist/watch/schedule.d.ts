/**
 * `pkgguard schedule install|status|remove`: run `pkgguard watch <dirs> --notify` on a timer.
 * Windows: a Task Scheduler task for the current user, started through a tiny .vbs so no
 * console window flashes up. macOS/Linux: print the crontab line to add.
 */
export declare const TASK_NAME = "pkgguard watch";
export interface Interval {
    unit: 'minute' | 'hour' | 'day';
    n: number;
}
/** "30m", "6h", "1d" (also "90min", "12 hours"). */
export declare function parseInterval(s: string): Interval;
/** schtasks /Create arguments. */
export declare function schtasksArgs(i: Interval, launcher: string): string[];
export declare function cronLine(i: Interval, command: string): string;
/** The watch command line: this node, this cli.js, absolute dirs. */
export declare function watchCommand(dirs: string[], extra?: string[]): {
    exe: string;
    args: string[];
};
export declare function installSchedule(dirs: string[], every: string, extra?: string[]): string;
export declare function scheduleStatus(): string;
export declare function runScheduleNow(): string;
export declare function removeSchedule(): string;
