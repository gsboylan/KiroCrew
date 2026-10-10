import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import AssistantMessage from '../pages/chat/AssistantMessage'

vi.mock('../components/MarkdownRenderer', () => ({
  default: ({ content }: { content: string }) => <div data-testid="md">{content}</div>,
}))
vi.mock('../hooks/useSmoothStream', () => ({ useSmoothStream: (content: string) => content }))
vi.mock('../utils/clipboard', () => ({
  copyToClipboard: vi.fn().mockResolvedValue(true),
  copyRichToClipboard: vi.fn().mockResolvedValue(true),
}))
import { copyRichToClipboard, copyToClipboard } from '../utils/clipboard'

const REPLY = '# Plan\n\n- **one**\n- two\n\nSee [docs](https://example.com).'

beforeEach(() => {
  vi.mocked(copyToClipboard).mockReset().mockResolvedValue(true)
  vi.mocked(copyRichToClipboard).mockReset().mockResolvedValue(true)
})

const openMore = () => fireEvent.pointerDown(
  screen.getByTestId('assistant-more-actions'), { button: 0, ctrlKey: false, pointerType: 'mouse' },
)
// Every surface that adds rich text: Copy in the row (Quote offered), Copy in More (Speak).
const QUOTED = { content: REPLY, isStreaming: false, slotRunning: false, onQuoteMessage: () => {} }
const VOICED = { content: REPLY, isStreaming: false, slotRunning: false, onSpeak: () => {} }

describe('AssistantMessage copy formats', () => {
  it('adds no footer control: the row Copy still copies Markdown on click', async () => {
    render(<AssistantMessage {...QUOTED} />)
    expect(screen.getByRole('button', { name: 'Copy' })).toHaveAttribute('title', 'Copy as Markdown')
    const row = screen.getByTestId('assistant-more-actions').parentElement!
    expect(Array.from(row.querySelectorAll(':scope > button')).map(b => b.getAttribute('aria-label'))).toEqual(['Quote message', 'Copy', 'More actions'])
    fireEvent.click(screen.getByRole('button', { name: 'Copy' }))
    await act(async () => {})
    expect(copyToClipboard).toHaveBeenCalledWith(REPLY)
    expect(copyRichToClipboard).not.toHaveBeenCalled()
  })

  it('More offers Copy as rich text with a hint naming where it pastes well', () => {
    render(<AssistantMessage {...QUOTED} />)
    openMore()
    const item = screen.getByTestId('copy-rich-menu-item')
    expect(item).toHaveTextContent('Copy as rich text')
    expect(item).toHaveTextContent('Keeps formatting in email and documents')
  })

  it('Copy as rich text writes clean HTML with the Markdown as plain text, and confirms in place', async () => {
    render(<AssistantMessage {...QUOTED} />)
    openMore()
    fireEvent.click(screen.getByTestId('copy-rich-menu-item'))
    await act(async () => {})
    expect(copyRichToClipboard).toHaveBeenCalledTimes(1)
    const [html, plain] = vi.mocked(copyRichToClipboard).mock.calls[0]
    expect(plain).toBe(REPLY)
    expect(html).toContain('<h1>Plan</h1>')
    expect(html).toContain('<strong>one</strong>')
    expect(html).toContain('<a href="https://example.com">docs</a>')
    expect(html).not.toMatch(/class=|style=/)
    expect(copyToClipboard).not.toHaveBeenCalled()
    // The menu stays open so the outcome is visible on the item itself, and
    // the hint gives way to it.
    expect(screen.getByTestId('copy-rich-menu-item')).toHaveTextContent('Copied as rich text')
    expect(screen.getByTestId('copy-rich-menu-item')).not.toHaveTextContent('Keeps formatting')
    // One confirmation per copy: the row's Markdown Copy does not also claim it.
    expect(screen.getByRole('button', { name: 'Copy', hidden: true })).toBeInTheDocument()
  })

  it('names the Markdown copy "Copy as Markdown" wherever it is a menu item', () => {
    render(<AssistantMessage {...VOICED} />)
    openMore()
    const md = screen.getByTestId('copy-message-menu-item')
    expect(md).toHaveTextContent('Copy as Markdown')
    expect(md).toHaveTextContent('Keeps ** and # symbols, for Markdown editors and chat apps')
    expect(screen.getAllByRole('menuitem').map(i => i.getAttribute('data-testid')).slice(0, 2)).toEqual(['copy-message-menu-item', 'copy-rich-menu-item'])
  })

  it('a refused rich write raises the copy-failed notice', async () => {
    vi.mocked(copyRichToClipboard).mockResolvedValueOnce(false)
    render(<AssistantMessage {...QUOTED} />)
    openMore()
    fireEvent.click(screen.getByTestId('copy-rich-menu-item'))
    await act(async () => {})
    expect(screen.getByRole('alert')).toBeInTheDocument()
  })

  it('the right-click menu offers both formats under the same names and hints', async () => {
    render(<AssistantMessage {...QUOTED} />)
    fireEvent.contextMenu(screen.getByTestId('message-bubble'))
    expect(screen.getByTestId('message-context-copy')).toHaveTextContent('Copy as MarkdownKeeps ** and # symbols, for Markdown editors and chat apps')
    expect(screen.getByTestId('message-context-copy-rich')).toHaveTextContent('Copy as rich textKeeps formatting in email and documents')
    fireEvent.click(screen.getByTestId('message-context-copy-rich'))
    await act(async () => {})
    expect(copyRichToClipboard).toHaveBeenCalledWith(expect.stringContaining('<h1>Plan</h1>'), REPLY)
  })

  it('a rich copy from the right-click menu confirms on the row Copy icon', async () => {
    render(<AssistantMessage {...QUOTED} />)
    fireEvent.contextMenu(screen.getByTestId('message-bubble'))
    fireEvent.click(screen.getByTestId('message-context-copy-rich'))
    await act(async () => {})
    // The tick names the format it is for, since the icon's own format is Markdown.
    expect(screen.getByRole('button', { name: 'Copied as rich text' })).toHaveAttribute('title', 'Copied as rich text')
  })


  it('a reply with no other menu gets More with both formats, folding its row actions into it', async () => {
    render(<AssistantMessage content={REPLY} isStreaming={false} slotRunning={false} messageTs="t1" slotKey="chat-1" onTogglePin={() => {}} />)
    const row = screen.getByTestId('assistant-more-actions').parentElement!
    expect(Array.from(row.querySelectorAll(':scope > button')).map(b => b.getAttribute('aria-label'))).toEqual(['Copy', 'More actions'])
    openMore()
    expect(screen.getAllByRole('menuitem').map(i => i.getAttribute('data-testid'))).toEqual(['copy-rich-menu-item', 'copy-link-menu-item', 'pin-menu-item', 'toggle-raw-view'])
    fireEvent.click(screen.getByTestId('copy-rich-menu-item'))
    await act(async () => {})
    expect(copyRichToClipboard).toHaveBeenCalledTimes(1)
  })

  it('a blank reply gets no menu just for copying nothing', () => {
    render(<AssistantMessage content={' \n '} isStreaming={false} slotRunning={false} />)
    expect(screen.queryByTestId('assistant-more-actions')).not.toBeInTheDocument()
  })
})
