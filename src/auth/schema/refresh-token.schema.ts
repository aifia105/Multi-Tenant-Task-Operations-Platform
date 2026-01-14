import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';

export type RefreshTokenDocument = RefreshToken & Document;

@Schema({ timestamps: true })
export class RefreshToken {
  @Prop({ required: true })
  userId: string;
  @Prop({ required: true })
  tokenHash: string;
  @Prop({ required: true })
  expiresAt: Date;
  _id: string;
}

export const RefreshTokenSchema = SchemaFactory.createForClass(RefreshToken);

RefreshTokenSchema.index(
  { userId: 1, token: 1 },
  { expireAfterSeconds: 60 * 60 * 24 * 7 },
);
