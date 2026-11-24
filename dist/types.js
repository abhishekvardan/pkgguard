export const ECOSYSTEMS = ['npm', 'PyPI', 'Go', 'crates.io', 'Maven', 'RubyGems', 'Packagist', 'NuGet'];
export const SEVERITY_RANK = {
    low: 1,
    unknown: 2, // never hide an advisory just because nobody scored it
    moderate: 2,
    high: 3,
    critical: 4,
};
