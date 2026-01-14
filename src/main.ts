import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import cookieParser from 'cookie-parser';
import csurf from 'csurf';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const configService = app.get(ConfigService);

  const config = new DocumentBuilder()
    .setTitle('Task & Operations Platform')
    .setDescription('The operations platform API description')
    .setVersion('1.0')
    .addTag('Task & Operations')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  const port = configService.get<number>('app.port');

  app.enableCors({
    origin: configService.get<string>('app.allowedClient'),
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: 'Content-Type, Authorization',
  });

  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
  app.use(cookieParser());

  app.use(csurf({ cookie: true }));

  await app.listen(port || 3000);

  console.log(
    '--------------------------------------------------------------------------------------',
  );
  console.log(
    `Server running on port ${process.env.PORT} and you can access the API at ${process.env.BACKEND_URL}:${process.env.PORT}`,
  );
  console.log(
    '--------------------------------------------------------------------------------------',
  );
  console.log(
    `Swagger documentation available at ${process.env.BACKEND_URL}:${process.env.PORT}/api`,
  );
  console.log(
    '--------------------------------------------------------------------------------------',
  );
}
bootstrap();
