import { NestFactory } from "@nestjs/core"
import { AppModule } from "./app.module"
import { ConfigService } from "@nestjs/config"
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger"
import { LoggingInterceptor } from "./common/interceptors/logging.interceptor"
import { ValidationPipe } from "@nestjs/common"

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  const configService = app.get(ConfigService)

  // Ensure hooks are called at the top level
  app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }))
  app.useGlobalInterceptors(new LoggingInterceptor())

  const swaggerConfig = new DocumentBuilder()
    .setTitle("Auth Service")
    .setDescription("Device detection and email verification API")
    .setVersion("1.0")
    .addBearerAuth()
    .build()
  const document = SwaggerModule.createDocument(app, swaggerConfig)
  SwaggerModule.setup("api", app, document)

  await app.listen(configService.get("app.port"))
}
bootstrap()
