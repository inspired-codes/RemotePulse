using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace InspiredCodes.RemotePulse.HubServer.Migrations
{
    /// <inheritdoc />
    public partial class PairingV2 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "Secret",
                table: "PendingCoPresences",
                newName: "PairingId");

            migrationBuilder.RenameColumn(
                name: "CoPresenceSecret",
                table: "Pairings",
                newName: "PairingId");

            migrationBuilder.AddColumn<string>(
                name: "AppBindTag",
                table: "PendingCoPresences",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AppBindTag",
                table: "Pairings",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AppBindTag",
                table: "PendingCoPresences");

            migrationBuilder.DropColumn(
                name: "AppBindTag",
                table: "Pairings");

            migrationBuilder.RenameColumn(
                name: "PairingId",
                table: "PendingCoPresences",
                newName: "Secret");

            migrationBuilder.RenameColumn(
                name: "PairingId",
                table: "Pairings",
                newName: "CoPresenceSecret");
        }
    }
}
