use std::fmt;

use iced::{
    Alignment, Length,
    widget::{column, pick_list, row, text_editor, text_input},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Alphabet {
    German,
    British,
    Nato,
}

impl Alphabet {
    const ALL: [Self; 3] = [Self::German, Self::British, Self::Nato];

    fn for_locale(locale: &str) -> Option<Self> {
        if locale.split('-').next()?.eq_ignore_ascii_case("de") {
            Some(Self::German)
        } else if locale.eq_ignore_ascii_case("en-GB") {
            Some(Self::British)
        } else {
            None
        }
    }

    fn spell(self, input: &str) -> String {
        let words = match self {
            Self::German => [
                "Anton",
                "Berta",
                "Cäsar",
                "Dora",
                "Emil",
                "Friedrich",
                "Gustav",
                "Heinrich",
                "Ida",
                "Julius",
                "Kaufmann",
                "Ludwig",
                "Martha",
                "Nordpol",
                "Otto",
                "Paula",
                "Quelle",
                "Richard",
                "Samuel",
                "Theodor",
                "Ulrich",
                "Viktor",
                "Wilhelm",
                "Xanthippe",
                "Ypsilon",
                "Zacharias",
            ],
            Self::British => [
                "Apple", "Beer", "Charlie", "Dog", "Edward", "Freddie", "George", "Harry", "Ink",
                "Johnnie", "King", "London", "Monkey", "Nuts", "Orange", "TT", "Queen", "Robert",
                "Sugar", "Toc", "Uncle", "Vic", "William", "X-ray", "Yorker", "Zed",
            ],
            Self::Nato => [
                "Alfa", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India",
                "Juliett", "Kilo", "Lima", "Mike", "November", "Oscar", "Papa", "Quebec", "Romeo",
                "Sierra", "Tango", "Uniform", "Victor", "Whiskey", "X-ray", "Yankee", "Zulu",
            ],
        };

        let mut output = String::new();
        let mut previous_was_word = false;
        for character in input.chars() {
            let word = match character.to_ascii_uppercase() {
                letter @ 'A'..='Z' => Some(words[usize::from(letter as u8 - b'A')]),
                'Ä' | 'ä' if self == Self::German => Some("Ärger"),
                'Ö' | 'ö' if self == Self::German => Some("Ökonom"),
                'Ü' | 'ü' if self == Self::German => Some("Übermut"),
                'ẞ' | 'ß' if self == Self::German => Some("Eszett"),
                '-' => Some("Minus"),
                '.' if self == Self::German => Some("Punkt"),
                '.' => Some("Dot"),
                _ => None,
            };
            if let Some(word) = word {
                if output.ends_with(|last: char| !last.is_whitespace()) {
                    output.push(' ');
                }
                output.push_str(word);
            } else {
                if previous_was_word && !character.is_whitespace() {
                    output.push(' ');
                }
                output.push(character);
            }
            previous_was_word = word.is_some();
        }
        output
    }
}

impl fmt::Display for Alphabet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::German => "German",
            Self::British => "British",
            Self::Nato => "NATO",
        })
    }
}

#[derive(Clone)]
pub enum Message {
    InputChanged(String),
    AlphabetChanged(Alphabet),
    OutputAction(text_editor::Action),
}

pub struct State {
    input: String,
    alphabet: Alphabet,
    output: text_editor::Content,
}

impl State {
    pub const TITLE: &'static str = "Spelling Alphabet";

    pub fn new() -> crate::OpenedModule {
        let state = Self {
            input: String::new(),
            alphabet: sys_locale::get_locales()
                .find_map(|locale| Alphabet::for_locale(&locale))
                .unwrap_or(Alphabet::Nato),
            output: text_editor::Content::new(),
        };
        (crate::Module::SpellingAlphabet(state), iced::Task::none())
    }

    pub fn update(&mut self, message: Message) {
        match message {
            Message::InputChanged(input) => self.input = input,
            Message::AlphabetChanged(alphabet) => self.alphabet = alphabet,
            Message::OutputAction(action) => {
                if !action.is_edit() {
                    self.output.perform(action);
                }
                return;
            }
        }
        self.output = text_editor::Content::with_text(&self.alphabet.spell(&self.input));
    }

    pub fn view(&self) -> iced::Element<'_, Message> {
        column![
            row![
                text_input("Text to spell", &self.input)
                    .on_input(Message::InputChanged)
                    .width(Length::Fill)
                    .size(18)
                    .padding([12, 16])
                    .style(crate::rounded_input_style),
                pick_list(Alphabet::ALL, Some(self.alphabet), Message::AlphabetChanged)
                    .padding([12, 16]),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            text_editor(&self.output)
                .placeholder("Spelled text")
                .on_action(Message::OutputAction)
                .padding(16)
                .height(Length::Fill),
        ]
        .padding(24)
        .spacing(16)
        .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spells_letters_and_keeps_digits_and_symbols() {
        assert_eq!(
            Alphabet::German.spell("Hä12@.x"),
            "Heinrich Ärger 12@ Punkt Xanthippe"
        );
        assert_eq!(Alphabet::British.spell("H"), "Harry");
        assert_eq!(Alphabet::Nato.spell("H"), "Hotel");
    }

    #[test]
    fn spells_hyphens_and_periods_in_each_alphabet() {
        assert_eq!(Alphabet::German.spell("1-.2"), "1 Minus Punkt 2");
        assert_eq!(Alphabet::British.spell("1-.2"), "1 Minus Dot 2");
        assert_eq!(Alphabet::Nato.spell("1-.2"), "1 Minus Dot 2");
    }

    #[test]
    fn matches_german_and_british_locale_preferences() {
        assert!(Alphabet::for_locale("de-AT") == Some(Alphabet::German));
        assert!(Alphabet::for_locale("en-gb") == Some(Alphabet::British));
        assert!(Alphabet::for_locale("en-US").is_none());
    }
}
