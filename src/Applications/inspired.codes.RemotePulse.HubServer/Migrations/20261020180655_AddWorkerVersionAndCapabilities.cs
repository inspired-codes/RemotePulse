using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace InspiredCodes.RemotePulse.HubServer.Migrations
{
    /// <inheritdoc />
    public partial class AddWorkerVersionAndCapabilities : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "WorkerCapabilities",
                table: "Clients",
                type: "character varying(528)",
                maxLength: 528,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "WorkerVersion",
                table: "Clients",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "WorkerCapabilities",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "WorkerVersion",
                table: "Clients");
        }
    }
}
