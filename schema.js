import * as z from 'zod';

const playerSchema = z.object({
  name: z.string().min(1),
  lastEventPoints: z.number(),
  totalPoints: z.number(),
});

const playlistSchema = z.object({
  playlistName: z.string().min(1),
  playlistDate: z.string().min(1),
  numberOfEvents: z.number(),
  numberOfPlayers: z.number(),
  uploadDate: z.string().min(1),
  uploadedBy: z.string().min(1),
  players: z.array(playerSchema).nonempty(),
});

const parsedImageSchema = z.object({
  playlistName: z.string(),
  numberOfEvents: z.number(),
  numberOfPlayers: z.number(),
  players: z.array(playerSchema),
});

export { playlistSchema, parsedImageSchema };