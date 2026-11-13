// Liquid Glass Design Tokens — HarmonyOS NEXT edition
// Ported from mailserver/webmail/src/lib/theme/tokens.css

export class ThemeColors {
  // Per-app accent — Mail Blue
  static readonly Accent: string = '#0A84FF';

  // Glass surfaces
  static readonly GlassBackground: string = 'rgba(255, 255, 255, 0.72)';
  static readonly GlassBackgroundDark: string = 'rgba(28, 28, 30, 0.72)';
  static readonly GlassBorder: string = 'rgba(255, 255, 255, 0.12)';

  // System colors
  static readonly Background: string = '#F2F2F7';
  static readonly BackgroundDark: string = '#000000';
  static readonly TextPrimary: string = '#1C1C1E';
  static readonly TextPrimaryDark: string = '#F2F2F7';
  static readonly TextSecondary: string = '#8E8E93';
  static readonly TextSecondaryDark: string = '#636366';
  static readonly Danger: string = '#FF453A';
  static readonly Success: string = '#30D158';

  // Hairlines (1px equivalent)
  static readonly Hairline: string = 'rgba(0, 0, 0, 0.08)';
  static readonly HairlineDark: string = 'rgba(255, 255, 255, 0.08)';

  private static darkMode: boolean = false;

  // Set dark mode from outside (called via @ohos.app.ability.Configuration)
  static setDarkMode(isDark: boolean): void {
    ThemeColors.darkMode = isDark;
  }

  static isDarkMode(): boolean {
    return ThemeColors.darkMode;
  }

  static bg(): string {
    return ThemeColors.isDarkMode() ? ThemeColors.BackgroundDark : ThemeColors.Background;
  }

  static text(): string {
    return ThemeColors.isDarkMode() ? ThemeColors.TextPrimaryDark : ThemeColors.TextPrimary;
  }

  static textDim(): string {
    return ThemeColors.isDarkMode() ? ThemeColors.TextSecondaryDark : ThemeColors.TextSecondary;
  }

  static glass(): string {
    return ThemeColors.isDarkMode() ? ThemeColors.GlassBackgroundDark : ThemeColors.GlassBackground;
  }

  static hairline(): string {
    return ThemeColors.isDarkMode() ? ThemeColors.HairlineDark : ThemeColors.Hairline;
  }
}

// macOS spring curve
export const SpringCurve: string = 'cubic-bezier(0.32, 0.72, 0, 1)';

// Animation durations (milliseconds)
export class Duration {
  static readonly Fast: number = 120;
  static readonly Default: number = 200;
  static readonly Slow: number = 320;
  static readonly PageTransition: number = 480;
}
