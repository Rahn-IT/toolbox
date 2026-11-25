use std::{f32::consts::TAU, time::Duration};

use iced::{
    Border, Event, Length, Point, Rectangle, Renderer, Size, Theme, Vector,
    advanced::{
        Clipboard, Layout, Renderer as _, Shell, Widget, layout, mouse, renderer,
        widget::{Tree, tree},
    },
    time::Instant,
    window,
};

use super::Message;

const SIZE: Length = Length::Fixed(36.0);
const INTERVAL: Duration = Duration::from_millis(65);
const DOTS: usize = 12;

pub(super) struct Spinner;

impl Widget<Message, Theme, Renderer> for Spinner {
    fn tag(&self) -> tree::Tag {
        tree::Tag::of::<Self>()
    }

    fn state(&self) -> tree::State {
        tree::State::new(Instant::now())
    }

    fn size(&self) -> Size<Length> {
        Size::new(SIZE, SIZE)
    }

    fn layout(
        &mut self,
        _tree: &mut Tree,
        _renderer: &Renderer,
        limits: &layout::Limits,
    ) -> layout::Node {
        layout::atomic(limits, SIZE, SIZE)
    }

    fn update(
        &mut self,
        _tree: &mut Tree,
        event: &Event,
        _layout: Layout<'_>,
        _cursor: mouse::Cursor,
        _renderer: &Renderer,
        _clipboard: &mut dyn Clipboard,
        shell: &mut Shell<'_, Message>,
        _viewport: &Rectangle,
    ) {
        if let Event::Window(window::Event::RedrawRequested(now)) = event {
            shell.request_redraw_at(*now + INTERVAL);
        }
    }

    fn draw(
        &self,
        tree: &Tree,
        renderer: &mut Renderer,
        theme: &Theme,
        _style: &renderer::Style,
        layout: Layout<'_>,
        _cursor: mouse::Cursor,
        _viewport: &Rectangle,
    ) {
        let elapsed = tree.state.downcast_ref::<Instant>().elapsed();
        let leading = (elapsed.as_millis() / INTERVAL.as_millis()) as usize % DOTS;
        let center = layout.bounds().center();
        let color = theme.extended_palette().primary.base.color;

        for index in 0..DOTS {
            let angle = index as f32 * TAU / DOTS as f32;
            let position: Point =
                center + Vector::new(13.0 * angle.cos() - 2.0, 13.0 * angle.sin() - 2.0);
            let distance = (leading + DOTS - index) % DOTS;
            let opacity = 1.0 - 0.8 * distance as f32 / (DOTS - 1) as f32;
            renderer.fill_quad(
                renderer::Quad {
                    bounds: Rectangle::new(position, Size::new(4.0, 4.0)),
                    border: Border::default().rounded(2.0),
                    snap: false,
                    ..renderer::Quad::default()
                },
                color.scale_alpha(opacity),
            );
        }
    }
}
