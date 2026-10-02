import { z } from 'zod';

/** Stable identifiers: published artwork and colours must never be reassigned. */
export const avatarShapeIds = [
  'shape-01', 'shape-02', 'shape-03', 'shape-04', 'shape-05',
  'shape-06', 'shape-07', 'shape-08', 'shape-09', 'shape-10',
  'shape-11', 'shape-12', 'shape-13', 'shape-14', 'shape-15',
  'shape-16', 'shape-17', 'shape-18', 'shape-19', 'shape-20',
] as const;
export const avatarColourIds = [
  'coral', 'amber', 'gold', 'lime', 'teal', 'mint',
  'sky', 'blue', 'indigo', 'violet', 'rose', 'slate',
] as const;
export const avatarSelection = z.strictObject({
  shapeId: z.enum(avatarShapeIds), colourId: z.enum(avatarColourIds),
});
export type AvatarSelection = z.infer<typeof avatarSelection>;
export const DEFAULT_AVATAR: Readonly<AvatarSelection> = Object.freeze({ shapeId: 'shape-01', colourId: 'teal' });
export const avatarColours = Object.freeze([
  { id: 'coral', label: 'Coral', hex: '#e97667' },
  { id: 'amber', label: 'Amber', hex: '#e79b47' },
  { id: 'gold', label: 'Gold', hex: '#d8b34a' },
  { id: 'lime', label: 'Lime', hex: '#a4bd56' },
  { id: 'teal', label: 'Teal', hex: '#43a89b' },
  { id: 'mint', label: 'Mint', hex: '#7abb99' },
  { id: 'sky', label: 'Sky', hex: '#69b4d8' },
  { id: 'blue', label: 'Blue', hex: '#6698d5' },
  { id: 'indigo', label: 'Indigo', hex: '#7b82cb' },
  { id: 'violet', label: 'Violet', hex: '#a083cf' },
  { id: 'rose', label: 'Rose', hex: '#ce7f9e' },
  { id: 'slate', label: 'Slate', hex: '#8b9dab' },
].map(colour => Object.freeze(colour)));

/** Presentation fallback only. Never insert defaults into signed historical content. */
export function resolveAvatarSelection(value: unknown): AvatarSelection {
  return avatarSelection.parse(value === undefined ? DEFAULT_AVATAR : value);
}
