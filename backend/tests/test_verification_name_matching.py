"""extract_candidate_packages() is a pure function (question + known package
list, no DB) -- these are fast, synthetic, fixture-free regression tests for
false-negative gaps found live in the fuzzy brand-name matcher (issue #39).
"""
from __future__ import annotations

from app.services.verification import extract_candidate_packages

KNOWN = [
    "com.nianticlabs.pokemongo",
    "com.disney.disneyplus",
    "ch.protonvpn.android",
    "com.google.android.apps.youtube.music",
    "com.eightball.pool",  # synthetic: stands in for a digit-containing brand's segment shape
]


def test_two_word_brand_with_a_two_letter_second_word_is_found():
    # Real gap found live: "Go" (2 chars) was dropped by the old len>2
    # filter before "pokemon"+"go" -> "pokemongo" was ever tried.
    found = extract_candidate_packages("The Pokemon Go app seemed to lag and glitch.", KNOWN)
    assert "com.nianticlabs.pokemongo" in found


def test_single_word_brand_missing_its_second_word_still_does_not_match():
    # Honest negative: "The Pokemon app" (no "Go" at all) genuinely has no
    # way to reconstruct the "pokemongo" segment -- "pokemon" alone is a
    # substring, not an exact segment match, and substring matching is
    # deliberately excluded (that's what let "and" false-match "android").
    # This must stay a non-match; verifying the fix didn't overcorrect into
    # loose substring matching.
    found = extract_candidate_packages("The Pokemon app seemed to lag and glitch.", KNOWN)
    assert "com.nianticlabs.pokemongo" not in found


def test_three_word_brand_name_concatenation_is_tried():
    # The old adjacent_concat only built 2-word pairs; a brand needing all
    # three words to reconstruct its segment had no path at all.
    found = extract_candidate_packages(
        "Did Eight Ball Pool crash while I was playing?",
        KNOWN + ["com.eightball.pool"],
    )
    # Sanity: package segment here is "eightballpool"-shaped only if all
    # three words concatenate; assert against a package whose segment
    # actually matches that 3-word concatenation.
    three_word_pkg = "com.eightballpool.game"
    found2 = extract_candidate_packages(
        "Did Eight Ball Pool crash while I was playing?",
        [three_word_pkg],
    )
    assert three_word_pkg in found2


def test_digit_in_brand_name_is_no_longer_dropped():
    # The old regex was letters-only ([A-Za-z]+), silently stripping any
    # digit before matching started.
    digit_pkg = "com.example.8ball"
    found = extract_candidate_packages("Did 8 Ball crash?", [digit_pkg])
    assert digit_pkg in found


def test_existing_two_word_and_single_word_regressions_still_pass():
    # Same cases the original two-word/single-word fixes covered -- confirm
    # this change didn't regress them.
    found = extract_candidate_packages(
        "watching Disney Plus while connected to VPN using Proton VPN", KNOWN,
    )
    assert "com.disney.disneyplus" in found
    assert "ch.protonvpn.android" in found

    found_solo = extract_candidate_packages("using ProtonVPN and Disney Plus", KNOWN)
    assert "ch.protonvpn.android" in found_solo
    assert "com.disney.disneyplus" in found_solo


def test_generic_single_word_still_requires_uniqueness_not_loosened():
    # "music" legitimately appears in multiple installed packages' segments
    # -- must still require 2 hits / a real concat, not be trusted alone.
    # Confirms the length-floor split didn't accidentally loosen this path.
    two_music_pkgs = [
        "com.google.android.apps.youtube.music",
        "com.spotify.music",
    ]
    found = extract_candidate_packages("was there an issue with music playback", two_music_pkgs)
    assert found == []
